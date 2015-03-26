#include "SharedObject.h"

#include <sys/types.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "Logger.h"
#include "Process.h"

namespace armhook {

SharedObject::SharedObject(string full_path)
	: ELF(full_path)
	, loadcmds_(NULL)
	, ncmds_(0)
	, load_size_(0)
	, load_start_(0)
	, load_bias_(0)
{
}

SharedObject::~SharedObject()
{
	/* free all segment structs */
	while (segments_.size()) {
		free(segments_.back());
		segments_.pop_back();
	}

	/* free all loadcmds */
	free(loadcmds_);
	loadcmds_ = NULL;
}

bool SharedObject::Injectable()
{
	return ehdr_->e_type == ET_DYN;
}

bool SharedObject::Inject(Process *proc)
{
	if (!ehdr_) {
		LOG_ERROR("library needs to be initialized first");
		return false;
	}

	if (!Injectable()) {
		LOG_ERROR("can only inject ET_DYN libraries");
		return false;
	}

	LOG_DEBUG("injecting library: %s", name_.c_str());
	if (!PrepareInjection() ||
		!ReserveMemory(proc) ||
		!MapSegments(proc) ||
		!LinkObject(proc))
		return false;

	return true;
}

bool SharedObject::set_base(Elf(Addr) base)
{
	load_start_ = load_bias_ = base;

	return true;
}

bool SharedObject::add_segment(Elf(Addr) start, Elf(Addr) end, char *prot)
{
	MemorySegment *seg = (MemorySegment*)calloc(1, sizeof(MemorySegment));
	if (!seg) {
		LOG_ERROR("couldn't allocate memory for a new segment");
		return false;
	}

	seg->start = start;
	seg->end = end;
	seg->prot = PROT_NONE;

	if (prot[0] == 'r')
		seg->prot |= PROT_READ;
	if (prot[1] == 'w')
		seg->prot |= PROT_WRITE;
	if (prot[2] == 'x')
		seg->prot |= PROT_EXEC;

	segments_.push_back(seg);
	LOG_DEBUG("added segment 0x%08x-0x%08x %4s to %s", start, end,
		prot, name_.c_str());

	return true;
}

MemorySegment* SharedObject::get_segment(Elf(Addr) addr)
{
	std::vector<MemorySegment*>::iterator it = segments_.begin();
	for (; it != segments_.end(); it++) {
		if ((*it)->start < addr && addr < (*it)->end)
			return (*it);
	}

	return NULL;
}

bool SharedObject::resolve(const char *symbol, Elf(Addr) &out, bool abs)
{
	if (!ELF::resolve(symbol, out))
		return false;

	if (abs)
		out += load_bias_;

	return true;
}

bool SharedObject::PrepareInjection()
{
	if (!ehdr_) {
		LOG_ERROR("ELF header not present");
		return false;
	}

	/* can only inject ET_DYN */
	if (ehdr_->e_type != ET_DYN) {
		LOG_ERROR("Object is not of type ET_DYN");
		return false;
	}

	uint16_t phnum = ehdr_->e_phnum;
	loadcmds_ = (LoadCommand*)calloc(phnum, sizeof(*loadcmds_));

	LoadCommand *cmd = NULL;
	for (uint16_t i=0; i<phnum; i++) {
		Elf(Phdr) *ph = &phdr_[i];

		switch(ph->p_type) {
		case PT_LOAD:
			cmd = &loadcmds_[ncmds_++];

			/* align everything properly */
			cmd->mapstart = PAGE_START(ph->p_vaddr);
                        cmd->mapend = PAGE_END(ph->p_vaddr + ph->p_filesz);
                        cmd->dataend = ph->p_vaddr + ph->p_filesz;
                        cmd->allocend = ph->p_vaddr + ph->p_memsz;
                        cmd->mapoff = PAGE_START(ph->p_offset);

                        cmd->prot = 0;
                        if (ph->p_flags & PF_R)
                                cmd->prot |= PROT_READ;
                        if (ph->p_flags & PF_W)
                                cmd->prot |= PROT_WRITE;
                        if (ph->p_flags & PF_X)
                                cmd->prot |= PROT_EXEC;
			break;
		}
	}

	load_size_ = loadcmds_[ncmds_-1].allocend - loadcmds_[0].mapstart;

	return true;
}

bool SharedObject::ReserveMemory(Process *proc)
{
	uint32_t base;

	PCALL(proc, mmap, &base, 0, load_size_, PROT_NONE,
		MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	LOG_DEBUG("mmap(): 0x%08x, %d, %d, ..., %d, 0x%08x",
		base, load_size_, PROT_NONE, -1, 0);

	if ((void*)base == MAP_FAILED) {
		LOG_ERROR("couldn't reserve memory mmap return: 0x%08x", base);
		return false;
	}

	load_start_ = base;
	load_bias_ = base - loadcmds_->mapstart;

	return true;
}

bool SharedObject::MapSegments(Process *proc)
{
	/* we need an open file descriptor for the library in the process */
	uint32_t name_addr = 0;
	PCALL(proc, malloc, &name_addr, full_path_.length());

	if (!name_addr) {
		LOG_ERROR("couldn't allocate memory inside the process");
		return false;
	}

	/* wrtie the path into the allocated memory in the process */
	if (!proc->WriteMemory(name_addr, full_path_.c_str(),
		full_path_.length())) {
		LOG_ERROR("coudln't write path: %s into process memory",
			full_path_.c_str());
		return false;
	}

	uint32_t fd = -1;
	PCALL(proc, open, (uint32_t*)&fd, name_addr, O_RDONLY, 0);
	if (fd < 0) {
		LOG_ERROR("process couldn't open library: %d", fd);
		return false;
	}

	LoadCommand *c = &loadcmds_[0];
	for (uint32_t i=0; i<ncmds_; i++) {
		uint32_t dummy = 0;
		uint32_t seg = c[i].mapstart + load_bias_;
		uint32_t length = c[i].mapend - c[i].mapstart;

		PCALL(proc, mmap, &dummy, seg, length, c[i].prot,
			MAP_FIXED | MAP_PRIVATE, fd, c[i].mapoff);

		if ((void*)dummy == MAP_FAILED) {
			LOG_ERROR("failed to mmap segment: 0x%08x", seg);
			return false;
		}

		uint32_t dataend = c[i].dataend + load_bias_;

		/* zero rest of the page */
		if ((c[i].prot & PROT_WRITE) && PAGE_OFFSET(dataend)) {
			length = PAGE_SIZE - PAGE_OFFSET(dataend);
			PCALL(proc, memset, &dummy, dataend, 0x0, length);
		}

		dataend = PAGE_END(dataend);

		uint32_t allocend = c[i].allocend + load_bias_;

		if (allocend > dataend) {
			PCALL(proc, mmap, &dummy, dataend,
				allocend - dataend, c[i].prot,
				MAP_FIXED | MAP_PRIVATE | MAP_ANON,
				-1, 0);

			if ((void*)dummy == MAP_FAILED) {
				LOG_ERROR("couldn't mmap zeor page: 0x%08x",
					dataend);
				return false;
			}
		}
	}

	PCALL(proc, close, NULL, fd);
	PCALL(proc, free, NULL, name_addr);

	return true;
}

bool SharedObject::LinkObject(Process *proc)
{
	/* if we have relocations in the .text section, make sure it is +w */
	if (textrel_ && !RemapSegments(proc, true)) {
		LOG_ERROR("failed to add write permissions for segments");
		return false;
	}

	if (plt_rel_) {
		if (!FixRelocations(proc, plt_rel_, num_plt_rel_)) {
			LOG_ERROR("failed to do DT_JMPREL relocations");
			return false;
		}
	}

	if (rel_) {
		if (!FixRelocations(proc, rel_, num_rel_)) {
			LOG_ERROR("failed to do DT_REL relocations");
			return false;
		}
	}

	/* restore original segment protection */
	if (textrel_ && !RemapSegments(proc)) {
		LOG_ERROR("failed to restore original segment permissions");
		return false;
	}

	if (!ProtectRelocations(proc)) {
		LOG_ERROR("couldn't mprotect relro region");
		return false;
	}

	return true;
}

bool SharedObject::FixRelocations(Process *proc, Elf(Rel) *rel, uint32_t count)
{
	SharedObject *so = NULL;

	for (uint32_t i=0; i<count; i++, rel++) {
		uint32_t type = ELF32_R_TYPE(rel->r_info);
		uint32_t sym = ELF32_R_SYM(rel->r_info);
		char *name = NULL;

		Elf(Addr) rel_pos = rel->r_offset + load_bias_;
		Elf(Addr) sym_addr = 0;
		Elf(Addr) old_val = 0;

		if (sym) {
			name = &strtab_[symtab_[sym].st_name];
			LOG_DEBUG("looking for symbol: %s", name);

			so = proc->lib_find(name, needed_);
			if (so) {
				so->resolve(name, sym_addr);
				LOG_DEBUG("found symbol: %s in %s at 0x%08x",
					name, so->name().c_str(), sym_addr);
			} else {
				/* TODO: handle not found */
			}
		} else {
			/* TODO: handle this */
		}

		switch (type) {
		case R_ARM_JUMP_SLOT:
			LOG_DEBUG("R_ARM_JUMP_SLOT [0x%08x] = 0x%08x [%s]",
				rel_pos, sym_addr, name);

			if (!proc->WriteMemory(rel_pos, (void*)&sym_addr,
				sizeof(sym_addr)))
				return false;
			break;
		case R_ARM_GLOB_DAT:
			LOG_DEBUG("R_ARM_GLOB_DAT [0x%08x] = 0x%08x [%s]",
				rel_pos, sym_addr, name);

			if (!proc->WriteMemory(rel_pos, (void*)&sym_addr,
				sizeof(sym_addr)))
				return false;
			break;
		case R_ARM_ABS32:
			LOG_DEBUG("R_ARM_ABS32 [0x%08x] += 0x%08x [%s]",
				rel_pos, sym_addr, name);

			old_val = 0;
			if (!proc->ReadMemory(rel_pos, (void*)&old_val,
				sizeof(old_val)))
				return false;

			old_val += sym_addr;

			if (!proc->WriteMemory(rel_pos, (void*)&old_val,
				sizeof(old_val)))
				return false;
			break;
		case R_ARM_REL32:
			LOG_DEBUG("R_ARM_REL32 [0x%08x] += 0x%08x - 0x%08x [%s]",
				rel_pos, sym_addr, rel->r_offset, name);

			old_val = 0;
			if (!proc->ReadMemory(rel_pos, (void*)&old_val,
				sizeof(old_val)))
				return false;

			old_val += sym_addr - rel->r_offset;

			if (!proc->WriteMemory(rel_pos, (void*)&old_val,
				sizeof(old_val)))
				return false;
			break;
		case R_ARM_RELATIVE:
			LOG_DEBUG("R_ARM_RELATIVE [0x%08x] += 0x%08x",
				rel_pos, load_start_);
			if (sym) {
				LOG_ERROR("ELF32_R_SYM can't be set with ARM_RELATIVE");
				return false;
			}

			old_val = 0;
			if (!proc->ReadMemory(rel_pos, (void*)&old_val,
				sizeof(old_val)))
				return false;

			old_val += load_start_;

			if (!proc->WriteMemory(rel_pos, (void*)&old_val,
				sizeof(old_val)))
				return false;
			break;
		case R_ARM_COPY:
			LOG_ERROR("R_ARM_COPY is not allowed in ET_DYN");
			return false;
			break;
		default:
			break;
		}
	}

	return true;
}

bool SharedObject::ProtectRelocations(Process *proc)
{
	Elf(Phdr) *ph = &phdr_[0];
	uint16_t phnum = ehdr_->e_phnum;

	uint32_t dummy = 0;

	for (uint16_t i=0; i<phnum; i++, ph++) {
		if (ph->p_type == PT_GNU_RELRO) {
			uint32_t start = PAGE_START(ph->p_vaddr) + load_bias_;
			uint32_t end = PAGE_END(ph->p_vaddr + ph->p_memsz) +
				load_bias_;

			PCALL(proc, mprotect, &dummy, start, end - start,
				PROT_READ);

			if (dummy < 0)
				LOG_WARN("failed to mprotect relocations at:" \
					"0x%08x", start);
		}
	}

	return true;
}

bool SharedObject::RemapSegments(Process *proc)
{
	return RemapSegments(proc, false);
}

bool SharedObject::RemapSegments(Process *proc, bool add_write)
{
	int dummy = 0;

	uint32_t ncmds = ncmds_;
	LoadCommand *c = &loadcmds_[0];

	for (uint32_t i=0; i<ncmds; i++) {
		uint32_t seg = c[i].mapstart + load_bias_;
		uint32_t len = c[i].mapend - c[i].mapstart;
		int32_t prot = c[i].prot;

		if (add_write)
			prot |= PROT_WRITE;

		PCALL(proc, mprotect, (uint32_t*)&dummy, seg, len, prot);
		if (dummy < 0) {
			LOG_ERROR("mprotect failed: 0x%08x, 0x%08x, 0x%08x",
				seg, len, prot);
			return false;
		}
	}

	return true;
}

} /* namespace armhook */
