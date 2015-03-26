#include "ELF.h"

#include <cstdlib>
#include <iostream>

#include "Logger.h"

namespace armhook {

ELF::ELF(std::string full_path)
	: ehdr_(NULL)
	, phdr_(NULL)
	, symtab_(NULL)
	, symsz_(0)
	, strtab_(NULL)
	, strsz_(0)
	, dyn_(NULL)
	, rel_(NULL)
	, num_rel_(0)
	, plt_rel_(NULL)
	, num_plt_rel_(0)
	, textrel_(false)
{
	full_path_ = full_path;

	unsigned pos = full_path.find_last_of("/");
	path_ = full_path.substr(0, pos);
	name_ = full_path.substr(pos+1);
}

ELF::~ELF()
{
	cleanup();
}

bool ELF::init()
{
	LOG_INFO("initializing library: %s", full_path_.c_str());
	bool rval = false;

	std::ifstream is(full_path_.c_str(), std::ifstream::binary);
	if (!is) {
		LOG_ERROR("couldn't open %s", full_path_.c_str());
		return false;
	}

	if (!read_ehdr(is) || !read_phdr(is) || !iterate_phdr(is) ||
		!iterate_dyn(is)) {
		rval = false;
	} else {
		rval = true;
	}

	is.close();
	return rval;
}

bool ELF::resolve(const char *symbol, Elf(Addr) &out)
{
	Elf(Sym) *sym = NULL;

	if (!symtab_ || !strtab_)
		return false;

	out = 0;
	for (Elf(Addr) i=0; i<(symsz_/sizeof(Elf(Sym))); i++) {
		sym = &symtab_[i];
		if (!strcmp(symbol, &strtab_[sym->st_name])) {
			out = sym->st_value;
			break;
		}
	}

	if (!out)
		return false;

	return true;
}

bool ELF::read_ehdr(std::ifstream &is)
{
	if (ehdr_)
		return true;

	/* allocate space for ELF header and read it */
	ehdr_ = (Elf(Ehdr)*)calloc(1, sizeof(*ehdr_));
	if (!ehdr_) {
		LOG_ERROR("failed to allocate memory for Ehdr");
		cleanup();
		return false;
	}

	is.read((char*)ehdr_, sizeof(*ehdr_));

	return true;
}

bool ELF::read_phdr(std::ifstream &is)
{
	if (phdr_)
		return true;

	if (!ehdr_)
		return false;

	/* allocate space for Program header array and read it */
	phdr_ = (Elf(Phdr)*)calloc(ehdr_->e_phnum, sizeof(*phdr_));
	if (!phdr_) {
		LOG_ERROR("failed to allocate memory for Phdr");
		cleanup();
		return false;
	}

	is.seekg(ehdr_->e_phoff);
	is.read((char*)phdr_, ehdr_->e_phnum * sizeof(*phdr_));

	return true;
}

bool ELF::iterate_phdr(std::ifstream &is)
{
	if (!ehdr_ || !phdr_)
		return false;

	bool rval = true;

	for (int32_t i=0; i<ehdr_->e_phnum; i++) {
		Elf(Phdr) *ph = &phdr_[i];

		switch(ph->p_type) {
		case PT_DYNAMIC:
			rval = read_dyn(is, ph);
			break;
		}

		if (!rval)
			return false;
	}

	return true;
}

bool ELF::read_dyn(std::ifstream &is, Elf(Phdr) *ph)
{
	if (dyn_)
		return true;

	dyn_ = (Elf(Dyn)*)calloc(1, ph->p_filesz);
	if (!dyn_) {
		LOG_ERROR("failed to allocate memory for Dyn array");
		cleanup();
		return false;
	}

	is.seekg(ph->p_offset);
	is.read((char*)dyn_, ph->p_filesz);

	return true;
}

bool ELF::iterate_dyn(std::ifstream &is)
{
	if (!dyn_)
		return false;

	Elf(Addr) rel = 0;
	Elf(Addr) plt_rel = 0;
	Elf(Addr) sym = 0;
	Elf(Addr) str = 0;

	Elf(Dyn) *dyn = &dyn_[0];
	for(; dyn->d_tag != DT_NULL; ++dyn) {
		switch(dyn->d_tag) {
		case DT_JMPREL:
			plt_rel = dyn->d_un.d_ptr;
			break;
		case DT_PLTRELSZ:
			num_plt_rel_ = dyn->d_un.d_val / sizeof(*plt_rel_);
			break;
		case DT_REL:
			rel = dyn->d_un.d_ptr;
			break;
		case DT_RELSZ:
			num_rel_ = dyn->d_un.d_val / sizeof(*rel_);
			break;
		case DT_SYMTAB:
			sym = dyn->d_un.d_ptr;
			break;
		case DT_STRTAB:
			str = dyn->d_un.d_ptr;
			break;
		case DT_STRSZ:
			strsz_ = dyn->d_un.d_val;
			break;
		case DT_TEXTREL:
			textrel_ = true;
			break;
		}
	}

	if (rel && !read_reloc(is, &rel_, rel, num_rel_))
		return false;

	if (plt_rel && !read_reloc(is, &plt_rel_, plt_rel, num_plt_rel_))
		return false;

	symsz_ = str - sym;
	if (sym && !read_table(is, (void**)&symtab_, sym, symsz_))
		return false;

	if (str && !read_table(is, (void**)&strtab_, str, strsz_))
		return false;

	/* we should have the string table, store dependency libraries */
	if (strtab_) {
		dyn = &dyn_[0];
		for (; dyn->d_tag != DT_NULL; ++dyn) {
			if (dyn->d_tag != DT_NEEDED)
				continue;

			needed_.push_back(std::string(&strtab_[dyn->d_un.d_val]));
		}
	}

	return true;
}

bool ELF::read_reloc(std::ifstream &is, Elf(Rel) **rel, Elf(Addr) pos,
	Elf32_Word count)
{
	if (*rel)
		return true;

	*rel = (Elf(Rel)*)calloc(count, sizeof(Elf(Rel)));
	if (!*rel) {
		cleanup();
		return false;
	}

	is.seekg(pos);
	is.read((char*)(*rel), count * sizeof(Elf(Rel)));

	return true;
}

bool ELF::read_table(std::ifstream &is, void **out, Elf(Addr) pos,
	Elf32_Word size)
{
	if (*out)
		return true;

	*out = calloc(1, size);
	if(!*out) {
		cleanup();
		return false;
	}

	is.seekg(pos);
	is.read((char*)(*out), size);

	return true;
}

void ELF::cleanup()
{
	free(ehdr_);
	ehdr_ = NULL;
	free(phdr_);
	phdr_ = NULL;
	free(symtab_);
	symtab_ = NULL;
	free(strtab_);
	strtab_ = NULL;
	free(dyn_);
	dyn_ = NULL;
	free(rel_);
	rel_ = NULL;
	free(plt_rel_);
	plt_rel_ = NULL;
}

} /* namespace armhook */
