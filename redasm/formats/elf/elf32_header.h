#ifndef ELF32_HEADER_H
#define ELF32_HEADER_H

#include "../../redasm.h"
#include "elf_common.h"

#define ELF32_R_SYM(i)     ((i) >> 8)
#define ELF32_R_TYPE(i)    ((unsigned char)(i))
#define ELF32_R_INFO(s, t) (((s) << 8) + ( unsigned char)(t))

namespace REDasm {

typedef u16 Elf32_Half;
typedef s16 Elf32_SHalf;
typedef u32 Elf32_Word;
typedef s32 Elf32_Sword;
typedef u64 Elf32_Xword;
typedef s64 Elf32_Sxword;

typedef u32 Elf32_Off;
typedef u32 Elf32_Addr;
typedef u16 Elf32_Section;

struct Elf32_Ehdr
{
    unsigned char e_ident[EI_NIDENT];
    Elf32_Half e_type, e_machine;
    Elf32_Word e_version;
    Elf32_Addr e_entry;
    Elf32_Off e_phoff, e_shoff;
    Elf32_Word e_flags;
    Elf32_Half e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx;
};

struct Elf32_Phdr
{
    Elf32_Word p_type;
    Elf32_Off p_offset;
    Elf32_Addr p_vaddr, p_paddr;
    Elf32_Word p_filesz, p_memsz, p_flags, p_align;
};

struct Elf32_Shdr
{
    Elf32_Word sh_name, sh_type, sh_flags;
    Elf32_Addr sh_addr;
    Elf32_Off sh_offset;
    Elf32_Word sh_size, sh_link, sh_info, sh_addralign, sh_entsize;
};

struct Elf32_Sym
{
    Elf32_Word st_name;
    Elf32_Addr st_value;
    Elf32_Word st_size;
    unsigned char st_info, st_other;
    Elf32_Half st_shndx;
};

struct Elf32_Rel
{
    Elf32_Addr r_offset;
    Elf32_Word r_info;
};

struct Elf32_Rela
{
    Elf32_Addr r_offset;
    Elf32_Word r_info;
    Elf32_Sword r_addend;
};

}

#endif // ELF32_HEADER_H
