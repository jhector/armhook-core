#ifndef ARMHOOK_PROCESS_H_
#define ARMHOOK_RPOCESS_H_

#include "ELF.h"

#include <stdint.h>

#include <string>
#include <vector>
#include <map>

#define OFFSETOF(type, field)	((unsigned long) &(((type *)0)->field))
#define SAFE_SP_OFFSET		0x100

#define PFUNC_DEFAULT_DECL(n, ...) \
	bool p_##n(__VA_ARGS__);

#define PCALL(obj, func, out, ...) \
	if (obj->p_##func(out, __VA_ARGS__) < 0) { \
		return false; \
	}

namespace armhook {

class SharedObject;
class Hook;

/*
 * Note: Entries 0-15 match r0..r15
 * Entry 16 is used to store the CPSR register
 * Entry 17 is used to store the "orig_r0" value.
 */
typedef struct { Elf(Addr) uregs[18]; } UserRegs;

class Process
{
public:
	Process(pid_t pid);
	~Process();

	bool Init(std::string libc_name);
	bool InitLibraries();

	bool Attach();
	bool Detach();

	bool Wait() { return Wait(NULL); }
	bool Wait(int *status);

	bool Run() { return Run(NULL); }
	bool Run(int *sig);

	bool WriteRegisters(UserRegs *regs);
	bool ReadRegisters(UserRegs *regs);

	bool WriteMemory(uint32_t addr, const void *in, int32_t length,
		bool preserve = false);
	bool ReadMemory(uint32_t addr, void *out, int32_t length);

	bool Resolve(std::string lib, std::string sym, Elf(Addr) &addr);

	int32_t Execute(uint32_t fn, uint32_t *args, uint32_t nargs,
		uint32_t *ret);

	bool Inject(std::string path);

	SharedObject* lib_find(const char *symbol,
		const std::vector<std::string> &needed);

	bool PrepareHooking();

	bool InsertHooks(const std::vector<Hook*> &hooks);
	bool InsertHook(Hook *hook);

	/* functions being called inside the process */
	PFUNC_DEFAULT_DECL(malloc, uint32_t*, uint32_t);
	PFUNC_DEFAULT_DECL(free, uint32_t*, uint32_t);
	PFUNC_DEFAULT_DECL(mmap, uint32_t*, uint32_t, uint32_t, uint32_t,
		uint32_t, uint32_t, uint32_t);
	PFUNC_DEFAULT_DECL(mprotect, uint32_t*, uint32_t, uint32_t, uint32_t);
	PFUNC_DEFAULT_DECL(open, uint32_t*, uint32_t, uint32_t, uint32_t);
	PFUNC_DEFAULT_DECL(close, uint32_t*, uint32_t);
	PFUNC_DEFAULT_DECL(memset, uint32_t*, uint32_t, uint32_t, uint32_t);

private:
	SharedObject* lib_get(std::string name);

	bool lib_check_deps(SharedObject *lib);

	std::map<std::string, SharedObject*> libs_;

	/* store common function addresses in the process */
	std::map<std::string, Elf(Addr)> common_functions_;

	pid_t pid_;
	bool attached_;
};

} /* namespace armhook */

#endif /* ARMHOOK_PROCESS_H_ */
