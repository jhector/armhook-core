#include "Process.h"

#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <string.h>
#include <fcntl.h>
#include <stdint.h>
#include <elf.h>
#include <signal.h>

#include <cstdio>
#include <cstdlib>
#include <iostream>
#include <fstream>
#include <string>

#include "ELF.h"
#include "SharedObject.h"
#include "Hook.h"
#include "Config.h"
#include "Decoder.h"
#include "Logger.h"

#define PFUNC_DEFAULT_BODY(n, ...) \
	uint32_t args[] = {__VA_ARGS__}, ret_value; \
	int32_t ret = -1; \
	if (common_functions_.find(#n) == common_functions_.end()) { \
		LOG_ERROR("address of '" #n "unkown for pid %d", pid_); \
		return false; \
	} \
	LOG_EXEC_FAIL(common_functions_[#n], args, sizeof(args)/sizeof(args[0]), \
		&ret_value); \
	\
	if (out) *out = ret_value; \
	return true;


#define PFUNC_DEFAULT_IMPL0(n) \
	bool Process::p_##n(uint32_t *out) \
	{ PFUNC_DEFAULT_BODY(n, 0); }

#define PFUNC_DEFAULT_IMPL1(n, a) \
	bool Process::p_##n(uint32_t *out, uint32_t a) \
	{ PFUNC_DEFAULT_BODY(n, a); }

#define PFUNC_DEFAULT_IMPL2(n, a, b) \
	bool Process::p_##n(uint32_t *out, uint32_t a, uint32_t b) \
	{ PFUNC_DEFAULT_BODY(n, a, b); }

#define PFUNC_DEFAULT_IMPL3(n, a, b, c) \
	bool Process::p_##n(uint32_t *out, uint32_t a, uint32_t b, uint32_t c) \
	{ PFUNC_DEFAULT_BODY(n, a, b, c); }

#define PFUNC_DEFAULT_IMPL4(n, a, b, c, d) \
	bool Process::p_##n(uint32_t *out, uint32_t a, uint32_t b, uint32_t c, \
		uint32_t d) \
	{ PFUNC_DEFAULT_BODY(n, a, b, c, d); }

#define PFUNC_DEFAULT_IMPL5(n, a, b, c, d, e) \
	bool Process::p_##n(uint32_t *out, uint32_t a, uint32_t b, uint32_t c, \
		uint32_t d, uint32_t e) \
	{ PFUNC_DEFAULT_BODY(n, a, b, c, d, e); }

#define PFUNC_DEFAULT_IMPL6(n, a, b, c, d, e, f) \
	bool Process::p_##n(uint32_t *out, uint32_t a, uint32_t b, uint32_t c, \
		uint32_t d, uint32_t e, uint32_t f) \
	{ PFUNC_DEFAULT_BODY(n, a, b, c, d, e, f); }

#define LOG_EXEC_FAIL(func, args, nargs, out) \
	if ((ret = Execute(func, args, nargs, out)) < 0) { \
		LOG_ERROR("failed to execute at 0x%08x. Pid: %d, Sig: %d, r15: 0x%08x", \
			func, pid_, ret, out); \
		return false; \
	}

namespace armhook {

Process::Process(pid_t pid)
	: pid_(pid)
	, attached_(false)
{}

Process::~Process()
{
	map<string, SharedObject*>::iterator it = libs_.begin();

	for (; it != libs_.end(); it++) delete (it->second);

	libs_.clear();
}

bool Process::Init(string libc_name)
{
	if (!InitLibraries())
		return false;

	SharedObject *lib = lib_get(libc_name);

	if (!lib) {
		LOG_ERROR("no libc library with name %s", libc_name.c_str());
		return false;
	}

	const char *syms[] = {"malloc", "free", "mmap", "mprotect", "open",
		"close", "memset"};

	for (uint32_t i=0; i<(sizeof(syms)/sizeof(syms[0])); i++) {
		Elf(Addr) val = 0;
		RESOLVE_SYM(lib, syms[i], val, true);

		common_functions_[syms[i]] = val;
	}

	return true;
}

bool Process::InitLibraries()
{
	Elf(Addr) start = 0;
	Elf(Addr) end = 0;

	char prot[5] = {0};
	char maps[128] = {0};
	char path[256] = {0};

	snprintf(maps, sizeof(maps), "/proc/%d/maps", pid_);
	ifstream is(maps);
	if (!is) {
		LOG_ERROR("ifstream open /proc/%d/maps failed", pid_);
		return false;
	}

	string line;
	while (getline(is, line)) {
		bzero(prot, sizeof(prot));
		bzero(path, sizeof(path));

		sscanf(line.c_str(), "%lx-%lx %s %*lx %*x:%*x %*u %s",
			&start, &end, prot, path);

		if (path[0] != '/')
                        continue;

		SharedObject *lib = NULL;
		if ((lib = lib_get(path))) {
			if (!lib->add_segment(start, end, prot))
				LOG_WARN("couldn't add segment at %08x to %s",
					start, path);
		} else {
			lib = new SharedObject(path);
			if (lib) {
				if (!lib->init() || !lib->set_base(start)) {
					LOG_WARN("failed creating library %s",
						path);

					delete lib;
					continue;
				}

				lib->add_segment(start, end, prot);

				libs_[lib->name()] = lib;
			} else {
				LOG_WARN("failed creating library %s",
					path);
			}
		}
	}

	is.close();
	return true;
}

bool Process::Attach()
{
	if (attached_)
		return true;

	if (ptrace(PTRACE_ATTACH, pid_, NULL, NULL) < 0) {
		int err = errno;
		LOG_ERROR("PTRACE_ATTACH with pid %d failed: %s",
			pid_, strerror(err));
		return false;
	}

	if (!Wait())
		return false;

	attached_ = true;
	return true;
}

bool Process::Detach()
{
	bool rc = 0;

	if (!attached_)
		return false;

	if (ptrace(PTRACE_DETACH, pid_, NULL, NULL) < 0) {
		int err = errno;
		LOG_ERROR("PTRACE_DETACH with pid %d failed: %s",
			pid_, strerror(err));
		rc = false;
	}

	attached_ = false;

	return rc;
}

bool Process::Wait(int *sig)
{
	int status = 0;

	if (waitpid(pid_, &status, 0) < 0) {
		int err = errno;
		LOG_ERROR("waitpid() on pid %d failed: %s",
			pid_, strerror(err));
		return false;
	}

	if (sig)
		*sig = WSTOPSIG(status);

	if (WIFEXITED(status) || WIFSIGNALED(status)) {
		LOG_ERROR("pid %d terminated", pid_);
		return false;
	}

	return true;
}

bool Process::Run(int *status)
{
	int sig = 0;

	if (!attached_)
		return false;

	while (!sig || sig == SIGSYS) {
		if (ptrace(PTRACE_CONT, pid_, NULL, sig) < 0) {
			int err = errno;
			LOG_ERROR("PTRACE_CONT with pid %d failed: %s",
					pid_, strerror(err));
			return false;
		}

		Wait(&sig);
	}

	if (status)
		*status = sig;

	return true;
}

bool Process::WriteRegisters(UserRegs *regs)
{
	if (!attached_) {
		LOG_WARN("WriteRegisters() but not attached");
		return false;
	}

	if (ptrace(PTRACE_SETREGS, pid_, NULL, regs) < 0) {
		int err = errno;
		LOG_ERROR("PTRACE_SETREGS with pid %d failed: %s",
			pid_, strerror(err));
		return false;
	}

	return true;
}

bool Process::ReadRegisters(UserRegs *regs)
{
	if (!attached_) {
		LOG_WARN("ReadRegisters() but not attached");
		return false;
	}

	if (ptrace(PTRACE_GETREGS, pid_, NULL, regs) < 0) {
		int err = errno;
		LOG_ERROR("PTRACE_GETREGS with pid %d failed: %s",
			pid_, strerror(err));
		return false;
	}

	return true;
}

bool Process::WriteMemory(uint32_t addr, const void *in, int32_t length,
	bool preserve /* = false */)
{
	uint32_t value = 0;
	uint32_t remain = 0;
	int32_t nwrites = length / 4;

	if (!attached_)
		return false;

	if ((remain = length % 4))
		nwrites++;

	for (int32_t i=0; i<nwrites; i++) {
		if (remain && (i == nwrites - 1)) {
			value = 0;

			if (preserve && !ReadMemory(addr, &value,
				sizeof(value))) {
				LOG_ERROR("couldn't read memory at 0x%08x for "
					"partial write", addr);
				return false;
			}

			for (uint32_t j=0; j<remain; j++) {
				((char*)&value)[j] =
					((char*)in)[i*sizeof(uint32_t)+j];
			}
		} else {
			value = ((uint32_t*)in)[i];
		}

		if (ptrace(PTRACE_POKEDATA, pid_, (void*)addr,
			(void*)value) < 0) {
			int err = errno;
			LOG_ERROR("PTRACE_POKEDATA with pid %d failed: %s",
				pid_, strerror(err));
			return false;
		}

		addr += sizeof(uint32_t);
	}

	return true;
}

bool Process::ReadMemory(uint32_t addr, void *out, int32_t length)
{
	uint32_t value = 0;
	uint32_t remain = 0;
	int32_t nreads = length / 4;

	if (!attached_)
		return false;

	if ((remain = length % 4))
		nreads++;

	for (int32_t i=0; i<nreads; i++) {
		value = ptrace(PTRACE_PEEKDATA, pid_, (void*)addr, NULL);

		if ((int32_t)value == -1 && errno != 0) {
			int err = errno;
			LOG_ERROR("PTRACE_PEEKDATA with pid %d failed: %s",
				pid_, strerror(err));
			return false;
		}

		if (remain && (i == nreads - 1)) {
			for (uint32_t j=0; j<remain; j++) {
				((char*)out)[i*sizeof(uint32_t)+j] =
					((char*)&value)[j];
			}
		} else {
			((uint32_t*)out)[i] = value;
		}

		addr += sizeof(uint32_t);
	}

	return true;
}

bool Process::Resolve(string lib, string sym, Elf(Addr) &addr)
{
	SharedObject *so = lib_get(lib);
	if (!so) {
		LOG_ERROR("couldn't find library %s", lib.c_str());
		addr = 0;
		return false;
	}

	RESOLVE_SYM(so, sym.c_str(), addr, true);

	return true;
}

int32_t Process::Execute(uint32_t fn, uint32_t *args, uint32_t nargs,
	uint32_t *ret)
{
	int32_t rc = 0;

	if (!attached_) {
		return -1;
	}

	/* save current register state to restore later */
	UserRegs old;
	if (!ReadRegisters(&old)) {
		return -1;
	}

	UserRegs call;
	memcpy(&call, &old, sizeof(call));

	/* move stack pointer to a safe location to maintain stack frames */
	call.uregs[13] -= SAFE_SP_OFFSET;

	/* set link regsiter to invalid value for controlled crash */
	call.uregs[14] = 0x4;

	/* set r15 (pc) to beginning of the called function */
	call.uregs[15] = fn;

	/* clear all flags except for mode bits */
	call.uregs[16] &= 0x1f;

	/* if target function has lsb set, switch to thumb mode */
	if (fn & 1)
		call.uregs[16] |= 0x20;

	/* first 4 arguments are stored in registers */
	for (int32_t i=0; i < 4 && i < (int32_t)nargs; i++) {
		call.uregs[i] = args[i];
	}

	/* according to calling convention, arguments 5+
	   are stored on the stack */
	if (nargs > 4) {
		WriteMemory(call.uregs[13], (void*)&args[4], (nargs-4)*4);
	}

	if (!WriteRegisters(&call)) {
		return -1;
	}

	int32_t sig = 0;
	if (!Run(&sig)) {
		return -1;
	}

	memset(&call, 0x00, sizeof(call));
	if (!ReadRegisters(&call)) {
		return -1;
	}

	if (sig != SIGSEGV || call.uregs[15] != 0x4) {
		rc = -sig;
		*ret = call.uregs[15];
	} else {
		*ret = call.uregs[0];
	}

	/* restore old registers */
	if (!WriteRegisters(&old)) {
		rc = -1;
	}

	return rc;
}

bool Process::Inject(string path)
{
	if (!attached_)
		return false;

	/* full path required */
	if (path.find("/") != 0) {
		LOG_ERROR("full path required for: %s", path.c_str());
		return false;
	}

	if (lib_get(path)) {
		LOG_INFO("library already injected: %s", path.c_str());
		return true;
	}

	SharedObject *lib = new SharedObject(path);
	if (!lib || !lib->init()) {
		LOG_ERROR("couldn't create SharedObject for %s", path.c_str());
		return false;
	}

	if (!lib->Injectable()) {
		LOG_ERROR("library isn't injectable");
		return false;
	}

	if (!lib_check_deps(lib)) {
		LOG_ERROR("missing library dependencies");
		return false;
	}

	if (!lib->Inject(this)) {
		LOG_ERROR("failed to inject library");
		return false;
	}

	/* add it to our library map */
	libs_[lib->name()] = lib;

	LOG_INFO("library %s injected", path.c_str());
	return true;
}

bool Process::PrepareHooking()
{
	if (!lib_get(Config::Instance()->helper()) &&
		!Inject(Config::Instance()->helper()))
		return false;

	SharedObject *helper = lib_get(Config::Instance()->helper());

	Elf(Addr) p_setup = 0;
	RESOLVE_SYM(helper, "setup", p_setup, true);

	uint32_t args[] = {0x80000000, 30};
        uint32_t loc = args[0], out = 0;
	Execute(p_setup, args, 2, &out);

	if ((out & loc) != loc) {
		LOG_ERROR("failed to setup trampoline at 0x%08x", loc);
		return false;
	}

	LOG_DEBUG("helper setup successful");

	return true;
}

bool Process::InsertHooks(const std::vector<Hook*> &hooks)
{
	bool ret_value = false;

	for (std::vector<Hook*>::const_iterator it = hooks.begin();
		it != hooks.end(); it++) {
		InsertHook((*it));
	}

	return ret_value;
}

bool Process::InsertHook(Hook *hook)
{
	if (!attached_)
		return false;

	/* check if helper library is injected */
	SharedObject *helper = lib_get(Config::Instance()->helper());
	if (!helper) {
		LOG_ERROR("armhook helper library %s isn't injected",
			Config::Instance()->helper());
		return false;
	}

	/* get function addresses that will help setting up the hook */
	Elf(Addr) p_hook_add = 0;
	RESOLVE_SYM(helper, "hook_add", p_hook_add, true);

	Elf(Addr) p_clearcache = 0;
	RESOLVE_SYM(helper, "clearcache", p_clearcache, true);

	uint32_t location = hook->location();

	if (hook->relative()) {
		SharedObject *base = lib_get(hook->base());
		if (!base) {
			LOG_ERROR("hook base %s is not mapped into memroy",
				hook->base());
			return false;
		}

		LOG_INFO("hook base [%s]: 0x%08x, offset: 0x%08x",
			hook->base(), base->load_start(), hook->location());

		location += base->load_start();
	}

	MemorySegment *seg = NULL;
	for (map<string, SharedObject*>::iterator it = libs_.begin();
		it != libs_.end(); it++) {
		seg = (it->second)->get_segment(location);
		if (seg) break;
	}

	if (!seg) {
		LOG_ERROR("memory location 0x%08x doesn't seem to be mapped",
			location);
		return false;
	}

	if (!(seg->prot & PROT_EXEC))
		LOG_WARN("segment isn't mapped executable, protection: %d",
			seg->prot);

	/* check if the library is injected that contains the handler */
	SharedObject *handler = lib_get(hook->library());
	if (!handler && !Inject(hook->library())) {
		LOG_ERROR("handler library %s couldn't be injected",
			hook->library());
		return false;
	}

	handler = lib_get(hook->library());

	/* get the address of the handler function */
	Elf(Addr) p_handler = 0;
	RESOLVE_SYM(handler, hook->handler(), p_handler, true);

	uint8_t detour[64] = {0}, detour_size = sizeof(detour);
	if (!hook->GetDetour(detour, &detour_size)) {
		LOG_ERROR("couldn't retrieve detour stub for hook");
		return false;
	}

	LOG_DEBUG("detour is %d bytes long", detour_size);

	/* get bytes at location and check how many need to be saved */
	uint8_t bytes[128] = {0}, save_amount = 0;

	/* don't forget to read from a 2 byte aligned address */
	if (!ReadMemory((location & 0xfffffffe), bytes, sizeof(bytes))) {
		LOG_ERROR("couldn't read at location 0x%08x", location);
		return false;
	}

	Decoder *decoder = new Decoder();
	if (!decoder->BytesToSave(bytes, (location & 1) ? false : true,
		detour_size, &save_amount) || save_amount < detour_size) {
		LOG_ERROR("failed to get amount of bytes to save: %d",
			save_amount);
		return false;
	}
	delete decoder;

	if (save_amount > detour_size)
		LOG_INFO("detour size is smaller then prolog bytes to save");

	/* use helper library to set the values for the array */
	int32_t h_idx = -1, ret = -1;
	uint32_t args[] = {p_handler, location, save_amount};
	LOG_EXEC_FAIL(p_hook_add, args, sizeof(args)/sizeof(args[0]),
		(uint32_t*)&h_idx);

	if (h_idx < 0) {
		LOG_ERROR("register hook failed: %d", h_idx);
		return false;
	}

	uint8_t padding = save_amount - detour_size;
	if (padding % 2) {
		LOG_ERROR("misaligned function prolog");
		return false;
	}

	uint8_t nops[16];
	if (padding && !hook->GetNops(nops, padding)) {
		LOG_ERROR("failed to retrieve nops for padding");
		return false;
	}

	/* write nop padding first (if required) */
	if (padding && !WriteMemory((location & 0xfffffffe), nops, padding)) {
		LOG_ERROR("couldn't write padding of size %d to 0x%08x",
			padding, (location & 0xffffffe));
		return false;
	}

	/* now overwrite the function prolog, mind alignment */
	if (!WriteMemory((location & 0xfffffffe) + padding, detour,
		detour_size, true)) {
		LOG_ERROR("couldn't write to memory at 0x%08x",
			(location & 0xffffffe) + padding);
		return false;
	}

	LOG_INFO("address: 0x%08x hooked with detour handler: %s",
		location, hook->handler());

	uint32_t dummy = 0;
	args[0] = seg->start;
	args[1] = seg->end;

	int32_t out = -1;
	LOG_EXEC_FAIL(p_clearcache, args, 2, &dummy);
	LOG_DEBUG("cache cleared for hook");

	return true;
}

/* default implementations for calling a libc function inside the process */
PFUNC_DEFAULT_IMPL1(malloc, size);
PFUNC_DEFAULT_IMPL1(free, ptr);
PFUNC_DEFAULT_IMPL6(mmap, addr, len, prot, flags, fd, offset);
PFUNC_DEFAULT_IMPL3(mprotect, addr, len, prot);
PFUNC_DEFAULT_IMPL3(open, pathname, flags, mode);
PFUNC_DEFAULT_IMPL1(close, fd);
PFUNC_DEFAULT_IMPL3(memset, s, c, n);

SharedObject* Process::lib_get(string name)
{
	if (name.find_last_of("/") != string::npos)
		name = name.substr(name.find_last_of("/")+1);

	map<string, SharedObject*>::iterator it = libs_.find(name);

	if (it == libs_.end())
		return NULL;

	return it->second;
}

SharedObject* Process::lib_find(const char *symbol,
	const vector<string> &needed)
{
	Elf(Addr) loc;
	SharedObject *lib = NULL;

	vector<string>::const_iterator it = needed.begin();
	for (; it != needed.end(); it++) {
		lib = lib_get((*it));
		lib->resolve(symbol, loc);

		if (loc)
			return lib;
	}

	return NULL;
}

bool Process::lib_check_deps(SharedObject *lib)
{
	vector<string>::const_iterator it = lib->needed().begin();

	for (; it != lib->needed().end(); it++) {
		if (lib_get((*it)) == NULL) {
			LOG_ERROR("dependency library: %s not loaded",
				(*it).c_str());
			return false;
		}
	}

	return true;
}

} /* namespace armhook */
