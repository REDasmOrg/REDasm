#include "elf.h"

namespace REDasm {

Elf32Format::Elf32Format(Buffer &buffer): ElfFormat<ELF_PARAMS(32)>(buffer) { }

bool Elf32Format::validate() const
{
    if(!ElfFormat<ELF_PARAMS(32)>::validate())
        return false;

    return this->bits() == 32;
}

u64 Elf32Format::relocationSymbol(const Elf32_Rel *rel) const { return ELF32_R_SYM(rel->r_info); }
Elf64Format::Elf64Format(Buffer &buffer): ElfFormat<ELF_PARAMS(64)>(buffer) { }

bool Elf64Format::validate() const
{
    if(!ElfFormat<ELF_PARAMS(64)>::validate())
        return false;

    return this->bits() == 64;
}

u64 Elf64Format::relocationSymbol(const Elf64_Rel *rel) const { return ELF64_R_SYM(rel->r_info); }

}
