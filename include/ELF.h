#ifndef ARMHOOK_ELF_H_
#define ARMHOOK_ELF_H_

#include <stdint.h>
#include <elf.h>

#include <vector>
#include <string>
#include <fstream>

#if __x86_64__
#define Elf(x) Elf64_##x
#else
#define Elf(x) Elf32_##x
#endif

#define PAGE_OFFSET(P)  ((uint32_t)(P) & (PAGE_SIZE-1))
#define PAGE_START(P)   ((uint32_t)(P) & ~(PAGE_SIZE-1))
#define PAGE_END(P)     (((uint32_t)(P) + PAGE_SIZE - 1) & ~(PAGE_SIZE-1))

namespace armhook {

class ELF
{
public:
	ELF(std::string full_path);
	~ELF();

	bool init();

	bool resolve(const char *symbol, Elf(Addr) &out);

	const std::string& full_path() const { return full_path_; }
	const std::string& path() const { return path_; }
	const std::string& name() const { return name_; }
	const std::vector<std::string>& needed() const { return needed_; }

	bool textrel() const { return textrel_; }

private:
	bool read_ehdr(std::ifstream &is);
	bool read_phdr(std::ifstream &is);

	bool iterate_phdr(std::ifstream &is);

	bool read_dyn(std::ifstream &is, Elf(Phdr) *ph);

	bool iterate_dyn(std::ifstream &is);

	bool read_reloc(std::ifstream &is, Elf(Rel) **rel, Elf(Addr) pos,
		Elf32_Word count);

	bool read_table(std::ifstream &is, void **out, Elf(Addr) pos,
		Elf32_Word size);

	void cleanup();

	std::string full_path_;
	std::string path_;
	std::string name_;

	std::vector<std::string> needed_;
	
	/* parts of the ELF file */
	Elf(Ehdr) *ehdr_; /* ELF header */
	Elf(Phdr) *phdr_; /* Program header array */

	Elf(Sym) *symtab_; /* DT_SYMTAB[] */
	Elf(Addr) symsz_;

	char *strtab_; /* DT_STRTAB[] */
	Elf32_Word strsz_;

	Elf(Dyn) *dyn_; /* PT_DYNAMIC[] */

	Elf(Rel) *rel_; /* DT_REL[] */
	Elf32_Word num_rel_; /* num entries */

	Elf(Rel) *plt_rel_; /* DT_JMPREL[] */
	Elf32_Word num_plt_rel_; /* num entries */

	bool textrel_; /* DT_TEXTREL present */

	friend class SharedObject;
};

} /* namespace armhook */

#endif /* ARMHOOK_ELF_H_ */
