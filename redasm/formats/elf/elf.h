#ifndef ELF_H
#define ELF_H

#include "../../plugins/plugins.h"
#include "elf32_header.h"
#include "elf64_header.h"

#define ELF_T(bits, t) Elf ## bits ## _ ## t
#define ELF_PARAMS_T typename EHDR, typename PHDR, typename SHDR, typename SYM, typename REL, typename RELA
#define ELF_PARAMS_D EHDR, PHDR, SHDR, SYM, REL, RELA
#define ELF_PARAMS(bits) ELF_T(bits, Ehdr), ELF_T(bits, Phdr), ELF_T(bits, Shdr), ELF_T(bits, Sym), ELF_T(bits, Rel), ELF_T(bits, Rela)

#define POINTER(T, offset) FormatPluginT<EHDR>::template pointer<T>(offset)
#define STRING_TABLE this->_shdr[this->_format->e_shstrndx];
#define STRING(shdr, offset) POINTER(const char, (shdr)->sh_offset + offset)

namespace REDasm {

template<ELF_PARAMS_T> class ELFFormat: public FormatPluginT<EHDR>
{
    public:
        ELFFormat(): FormatPluginT<EHDR>(), _phdr(NULL), _shdr(NULL) { }
        virtual const char* name() const { return "ELF Format"; }
        virtual u32 bits() const;
        virtual const char* assembler() const;
        virtual bool load(u8* format);

    protected:
        virtual bool validate() const;
        virtual u64 relocationSymbol(const REL* rel) const = 0;

    private:
        bool relocate(u64 symidx, u64* value) const;
        void loadSegment(const SHDR& shdr);
        void loadSymbols(const SHDR& shdr);
        void parseProgramHeader();
        void parseSections();

    private:
        PHDR* _phdr;
        SHDR* _shdr;
};

template<ELF_PARAMS_T> u32 ELFFormat<ELF_PARAMS_D>::bits() const
{
    if(this->_format->e_ident[EI_CLASS] == ELFCLASS32)
        return 32;

    if(this->_format->e_ident[EI_CLASS] == ELFCLASS64)
        return 64;

    return 0;
}

template<ELF_PARAMS_T> const char* ELFFormat<ELF_PARAMS_D>::assembler() const
{
    switch(this->_format->e_machine)
    {
        case EM_386:
            return "x86_32";

        case EM_X86_64:
            return "x86_64";

        case EM_MIPS:
            return this->bits() == 32 ? "mips32" : "mips64";

        case EM_ARM:
            return this->bits() == 32 ? "arm" : "arm64";

        default:
            break;
    }

    return NULL;
}

template<ELF_PARAMS_T> bool ELFFormat<ELF_PARAMS_D>::load(u8* format)
{
    EHDR* ehdr = this->convert(format);

    if(!this->validate() || !this->bits())
        return false;

    this->_phdr = POINTER(PHDR, ehdr->e_phoff);
    this->_shdr = POINTER(SHDR, ehdr->e_shoff);
    this->defineEntryPoint(this->_format->e_entry);
    this->parseSections();
    this->parseProgramHeader();

    FormatPluginT<EHDR>::load(format);
    return true;
}

template<ELF_PARAMS_T> bool ELFFormat<ELF_PARAMS_D>::relocate(u64 symidx, u64* value) const
{
    for(u64 i = 0; i < this->_format->e_shnum; i++)
    {
        const SHDR& shdr = this->_shdr[i];

        if((shdr.sh_type != SHT_REL) && (shdr.sh_type != SHT_RELA))
            continue;

        offset_t offset = shdr.sh_offset, endoffset = offset + shdr.sh_size;

        while(offset < endoffset)
        {
            REL* rel = POINTER(REL, offset);
            u64 sym = this->relocationSymbol(rel);

            if(sym == symidx)
            {
                *value = rel->r_offset;
                return true;
            }

            offset += (shdr.sh_type == SHT_REL) ? sizeof(REL) : sizeof(RELA);
        }
    }

    return false;
}

template<ELF_PARAMS_T> void ELFFormat<ELF_PARAMS_D>::loadSegment(const SHDR& shdr)
{
    const SHDR& shstr = STRING_TABLE;
    u32 type = SegmentTypes::Read | ((shdr.sh_flags & SHF_EXECINSTR) ? SegmentTypes::Code :
                                                                       SegmentTypes::Data);

    if(shdr.sh_flags & SHF_WRITE)
        type |= SegmentTypes::Write;

    this->defineSegment(STRING(&shstr, shdr.sh_name), shdr.sh_offset, shdr.sh_addr, shdr.sh_size, type);
}

template<ELF_PARAMS_T> void ELFFormat<ELF_PARAMS_D>::loadSymbols(const SHDR& shdr) // TODO: Improve symbol handling
{
    u64 idx = 0;
    offset_t offset = shdr.sh_offset, endoffset = offset + shdr.sh_size;
    const SHDR& shstr = shdr.sh_link ? this->_shdr[shdr.sh_link] : STRING_TABLE;

    while(offset < endoffset)
    {
        bool isrelocated = false;
        SYM* sym = POINTER(SYM, offset);
        u8 info = ELF_ST_TYPE(sym->st_info);
        u64 symvalue = sym->st_value;

        if(!symvalue)
            isrelocated = this->relocate(idx, &symvalue);

        if(!sym->st_name || !symvalue)
        {
            offset += sizeof(SYM);
            idx++;
            continue;
        }

        std::string symname = REDasm::demangle(STRING(&shstr, sym->st_name));

        if(!isrelocated)
        {
            bool isexport = false;
            u8 bind = ELF_ST_BIND(sym->st_info);
            u8 visibility = ELF_ST_VISIBILITY(sym->st_other);

            if(visibility == STV_DEFAULT)
                isexport = (bind == STB_GLOBAL) || (bind == STB_WEAK);
            else if(bind == STB_GLOBAL)
                isexport = true;

            if(isexport)
            {
                this->defineSymbol(symvalue, symname, (info == STT_FUNC) ? SymbolTypes::ExportFunction :
                                                                           SymbolTypes::ExportData);
            }
            else if(info == STT_FUNC)
                this->defineFunction(symvalue, symname);
            else if(info == STT_OBJECT)
                this->defineSymbol(symvalue, symname, SymbolTypes::Data);
        }
        else
            this->defineSymbol(symvalue, symname, SymbolTypes::Import);

        offset += sizeof(SYM);
        idx++;
    }
}

template<ELF_PARAMS_T> void ELFFormat<ELF_PARAMS_D>::parseProgramHeader()
{
    u32 loadidx = 0;

    for(u64 i = 0; i < this->_format->e_phnum; i++)
    {
        const PHDR& phdr = this->_phdr[i];

        if(phdr.p_type != PT_LOAD)
            continue;

        const Segment* segment = this->segment(phdr.p_vaddr);

        if(segment)
            continue;

        u32 flags = SegmentTypes::None;

        if(phdr.p_type & PF_X)
            flags |= SegmentTypes::Code;

        if(phdr.p_type & PF_R)
            flags |= SegmentTypes::Read;

        if(phdr.p_type & PF_W)
            flags |= SegmentTypes::Write;

        std::stringstream ss;
        ss << "LOAD" << loadidx++;

        this->defineSegment(ss.str(), phdr.p_offset, phdr.p_vaddr, phdr.p_memsz, flags);
    }
}

template<ELF_PARAMS_T> bool ELFFormat<ELF_PARAMS_D>::validate() const
{
    if(this->_format->e_ident[EI_MAG0] != ELFMAG0)
        return false;

    if(this->_format->e_ident[EI_MAG1] != ELFMAG1)
        return false;

    if(this->_format->e_ident[EI_MAG2] != ELFMAG2)
        return false;

    if(this->_format->e_ident[EI_MAG3] != ELFMAG3)
        return false;

    if(this->_format->e_ident[EI_VERSION] != EV_CURRENT)
        return false;

    return true;
}

template<ELF_PARAMS_T> void ELFFormat<ELF_PARAMS_D>::parseSections()
{
    for(u64 i = 0; i < this->_format->e_shnum; i++)
    {
        const SHDR& shdr = this->_shdr[i];

        if(shdr.sh_addr && (shdr.sh_type == SHT_PROGBITS))
            this->loadSegment(shdr);
        else if((shdr.sh_type == SHT_SYMTAB) || (shdr.sh_type == SHT_DYNSYM))
            this->loadSymbols(shdr);
    }
}

class Elf32Format: public ELFFormat<ELF_PARAMS(32)>
{
    public:
        Elf32Format();

    protected:
        virtual bool validate() const;
        virtual u64 relocationSymbol(const Elf32_Rel* rel) const;
};

class Elf64Format: public ELFFormat<ELF_PARAMS(64)>
{
    public:
        Elf64Format();

    protected:
        virtual bool validate() const;
        virtual u64 relocationSymbol(const Elf64_Rel* rel) const;
};

DECLARE_FORMAT_PLUGIN(Elf32Format, elf32)
DECLARE_FORMAT_PLUGIN(Elf64Format, elf64)

}

#endif // ELF_H
