#ifndef ELF_CONSTANTS_H
#define ELF_CONSTANTS_H

#define ELF_ST_BIND(i)       ((i) >> 4)
#define ELF_ST_TYPE(i)       ((i) & 0xF)
#define ELF_ST_INFO(b,t)     (((b) << 4) + ((t) & 0xF))
#define ELF_ST_VISIBILITY(o) ((o) & 0x3)

#define EI_NIDENT 16

#define EI_MAG0         0
#define EI_MAG1         1
#define EI_MAG2         2
#define EI_MAG3         3
#define EI_CLASS        4
#define EI_DATA         5
#define EI_VERSION      6
#define EI_OSABI        7
#define EI_PAD          8

#define ELFMAG0         0x7f
#define ELFMAG1         'E'
#define ELFMAG2         'L'
#define ELFMAG3         'F'

#define ELFCLASSNONE    0
#define ELFCLASS32      1
#define ELFCLASS64      2

#define EV_NONE         0
#define EV_CURRENT      1

#define EM_NONE         0
#define EM_M32          1
#define EM_SPARC        2
#define EM_386          3
#define EM_68K          4
#define EM_88K          5
#define EM_486          6
#define EM_860          7
#define EM_MIPS         8
#define EM_MIPS_RS4_BE  10
#define EM_PARISC       15
#define EM_SPARC32PLUS  18
#define EM_PPC          20
#define EM_PPC64        21
#define EM_S390         22
#define EM_ARM          40
#define EM_SH           42
#define EM_SPARCV9      43
#define EM_H8_300H      47
#define EM_H8S          48
#define EM_IA_64        50
#define EM_X86_64       62
#define EM_CRIS         76
#define EM_V850         87
#define EM_ALPHA        0x9026
#define EM_CYGNUS_V850  0x9080
#define EM_S390_OLD     0xA390

#define PT_NULL      0
#define PT_LOAD      1
#define PT_DYNAMIC     2
#define PT_INTERP     3
#define PT_NOTE      4
#define PT_SHLIB     5
#define PT_PHDR      6
#define PT_LOOS      0x60000000
#define PT_HIOS      0x6fffffff
#define PT_LOPROC     0x70000000
#define PT_HIPROC     0x7fffffff
#define PT_GNU_EH_FRAME 0x6474e550

#define PF_X            0x1
#define PF_W            0x2
#define PF_R            0x4

#define SHN_UNDEF       0
#define SHN_LORESERVE   0xff00
#define SHN_LOPROC      0xff00
#define SHN_HIPROC      0xff1f
#define SHN_ABS         0xfff1
#define SHN_COMMON      0xfff2
#define SHN_HIRESERVE   0xffff

#define SHT_NULL        0
#define SHT_PROGBITS    1
#define SHT_SYMTAB      2
#define SHT_STRTAB      3
#define SHT_RELA        4
#define SHT_HASH        5
#define SHT_DYNAMIC     6
#define SHT_NOTE        7
#define SHT_NOBITS      8
#define SHT_REL         9
#define SHT_SHLIB       10
#define SHT_DYNSYM      11
#define SHT_NUM         12
#define SHT_LOPROC      0x70000000
#define SHT_HIPROC      0x7fffffff
#define SHT_LOUSER      0x80000000
#define SHT_HIUSER      0xffffffff

#define SHF_WRITE       0x1
#define SHF_ALLOC       0x2
#define SHF_EXECINSTR   0x4
#define SHF_MASKPROC    0xf0000000

#define STB_LOCAL       0
#define STB_GLOBAL      1
#define STB_WEAK        2

#define STT_NOTYPE      0
#define STT_OBJECT      1
#define STT_FUNC        2
#define STT_SECTION     3
#define STT_FILE        4
#define STT_COMMON      5
#define STT_TLS         6

#define STV_DEFAULT     0
#define STV_INTERNAL 1
#define STV_HIDDEN     2
#define STV_PROTECTED 3

#endif // ELF_CONSTANTS_H
