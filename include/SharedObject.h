#ifndef ARMHOOK_SHAREDOBJECT_H_
#define ARMHOOK_SHAREDOBJECT_H_

#include <vector>

#include "ELF.h"

#define RESOLVE_SYM(obj, a, b, c) \
	if (!obj->resolve(a, b, c)) { \
		LOG_ERROR("couldn't resolve symbol %s in library: %s", \
			b, obj->name().c_str()); \
		return false; \
	}

namespace armhook {

class Process;

/* loadcmd struct like in elf/dl-load.h of glibc */
typedef struct {
        Elf(Addr) mapstart, mapend, dataend, allocend;
        Elf(Off) mapoff;
        int32_t prot;
} LoadCommand;

/* mapped segment in memory (/proc/<pid>/maps) */
typedef struct {
	Elf(Addr) start;
	Elf(Addr) end;
	int32_t prot;
} MemorySegment;

using namespace std;

class SharedObject : public ELF
{
public:
	SharedObject(std::string full_path);
	~SharedObject();

	bool Injectable();
	bool Inject(Process *proc);

	bool set_base(Elf(Addr) base);
	bool add_segment(Elf(Addr) start, Elf(Addr) end, char *prot);
	MemorySegment* get_segment(Elf(Addr) addr);

	bool resolve(const char *symbol, Elf(Addr) &out, bool abs = true);

	Elf(Addr) load_start() const { return load_start_; }

	LoadCommand *loadcmds_; /* mmap information for each PT_LOAD */
	uint16_t ncmds_; /* total PT_LOAD entries */

	uint32_t load_size_; /* total memory space to reserve for object */

private:
	bool PrepareInjection();

	bool ReserveMemory(Process *proc);

	bool MapSegments(Process *proc);

	bool LinkObject(Process *proc);

	bool FixRelocations(Process *proc, Elf(Rel) *rel, uint32_t count);

	bool ProtectRelocations(Process *proc);

	bool RemapSegments(Process *proc);
	bool RemapSegments(Process *proc, bool add_write);

	Elf(Addr) load_start_; /* base address in memory */
	Elf(Addr) load_bias_; /* first segment bias to align to page */

	std::vector<MemorySegment*> segments_;
};

} /* namespace armhook */

#endif /* ARMHOOK_SHAREDOBJECT_H_ */
