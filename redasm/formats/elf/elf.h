#ifndef ELF_H
#define ELF_H

#include "../../plugins/plugins.h"
#include "elf32_header.h"
#include "elf64_header.h"
#include "elf_analyzer.h"

#define ELF_T(bits, t) Elf ## bits ## _ ## t
#define ELF_PARAMS_T typename EHDR, typename SHDR, typename SYM, typename REL, typename RELA
#define ELF_PARAMS_D EHDR, SHDR, SYM, REL, RELA
#define ELF_PARAMS(bits) ELF_T(bits, Ehdr), ELF_T(bits, Shdr), ELF_T(bits, Sym), ELF_T(bits, Rel), ELF_T(bits, Rela)

#define POINTER(T, offset) FormatPluginT<EHDR>::template pointer<T>(offset)
#define ELF_STRING_TABLE this->m_shdr[this->m_format->e_shstrndx];
#define ELF_STRING(shdr, offset) POINTER(const char, (shdr)->sh_offset + offset)

namespace REDasm {

template<ELF_PARAMS_T> class ElfFormat: public FormatPluginT<EHDR>
{
    public:
        ElfFormat(Buffer& buffer): FormatPluginT<EHDR>(buffer), m_shdr(NULL) { }
        virtual const char* name() const { return "ELF Format"; }
        virtual u32 bits() const;
        virtual const char* assembler() const;
        virtual bool load();
        virtual Analyzer* createAnalyzer(DisassemblerAPI *disassembler, const SignatureFiles &signatures) const;

    protected:
        virtual bool validate() const;
        virtual u64 relocationSymbol(const REL* rel) const = 0;

    private:
        bool relocate(u64 symidx, u64* value) const;
        void loadSymbols(const SHDR& shdr);
        void loadSegments();
        void parseSegments();

    private:
        SHDR* m_shdr;
};

template<ELF_PARAMS_T> u32 ElfFormat<ELF_PARAMS_D>::bits() const
{
    if(this->m_format->e_ident[EI_CLASS] == ELFCLASS32)
        return 32;

    if(this->m_format->e_ident[EI_CLASS] == ELFCLASS64)
        return 64;

    return 0;
}

template<ELF_PARAMS_T> const char* ElfFormat<ELF_PARAMS_D>::assembler() const
{
    switch(this->m_format->e_machine)
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

template<ELF_PARAMS_T> bool ElfFormat<ELF_PARAMS_D>::load()
{
    if(!this->validate() || !this->bits())
        return false;

    this->m_shdr = POINTER(SHDR, this->m_format->e_shoff);
    this->loadSegments();
    this->parseSegments();
    this->m_document.entry(this->m_format->e_entry);

    return true;
}

template<ELF_PARAMS_T> Analyzer* ElfFormat<ELF_PARAMS_D>::createAnalyzer(DisassemblerAPI *disassembler, const SignatureFiles &signatures) const
{
    return new ElfAnalyzer(disassembler, signatures);
}

template<ELF_PARAMS_T> bool ElfFormat<ELF_PARAMS_D>::relocate(u64 symidx, u64* value) const
{
    for(u64 i = 0; i < this->m_format->e_shnum; i++)
    {
        const SHDR& shdr = this->m_shdr[i];

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

template<ELF_PARAMS_T> void ElfFormat<ELF_PARAMS_D>::loadSegments()
{
    const SHDR& shstr = ELF_STRING_TABLE;

    for(u64 i = 0; i < this->m_format->e_shnum; i++)
    {
        const SHDR& shdr = this->m_shdr[i];

        if(!shdr.sh_addr)
            continue;

        u32 type = SegmentTypes::Read;

        if((shdr.sh_type & SHT_PROGBITS) && (shdr.sh_flags & SHF_EXECINSTR))
            type |= SegmentTypes::Code;
        else
            type |= SegmentTypes::Data;

        if(shdr.sh_type & SHT_NOBITS)
            type |= SegmentTypes::Bss;

        if(shdr.sh_flags & SHF_WRITE)
            type |= SegmentTypes::Write;

        this->m_document.segment(ELF_STRING(&shstr, shdr.sh_name), shdr.sh_offset, shdr.sh_addr, shdr.sh_size, type);
    }
}

template<ELF_PARAMS_T> void ElfFormat<ELF_PARAMS_D>::loadSymbols(const SHDR& shdr)
{
    offset_t offset = shdr.sh_offset, endoffset = offset + shdr.sh_size;
    const SHDR& shstr = shdr.sh_link ? this->m_shdr[shdr.sh_link] : ELF_STRING_TABLE;

    for(u64 idx = 0; offset < endoffset; idx++)
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
            continue;
        }

        std::string symname = ELF_STRING(&shstr, sym->st_name);

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
                this->m_document.lock(symvalue, symname, (info == STT_FUNC) ? SymbolTypes::ExportFunction : SymbolTypes::ExportData);
            else if(info == STT_FUNC)
                this->m_document.function(symvalue, symname);
            else if(info == STT_OBJECT)
                this->m_document.lock(symvalue, symname, SymbolTypes::Data);
        }
        else
            this->m_document.lock(symvalue, symname, SymbolTypes::Import);

        offset += sizeof(SYM);
    }
}

template<ELF_PARAMS_T> bool ElfFormat<ELF_PARAMS_D>::validate() const
{
    if(this->m_format->e_ident[EI_MAG0] != ELFMAG0)
        return false;

    if(this->m_format->e_ident[EI_MAG1] != ELFMAG1)
        return false;

    if(this->m_format->e_ident[EI_MAG2] != ELFMAG2)
        return false;

    if(this->m_format->e_ident[EI_MAG3] != ELFMAG3)
        return false;

    if(this->m_format->e_ident[EI_VERSION] != EV_CURRENT)
        return false;

    return true;
}

template<ELF_PARAMS_T> void ElfFormat<ELF_PARAMS_D>::parseSegments()
{
    for(u64 i = 0; i < this->m_format->e_shnum; i++)
    {
        const SHDR& shdr = this->m_shdr[i];

        if(shdr.sh_offset && ((shdr.sh_type == SHT_SYMTAB) || (shdr.sh_type == SHT_DYNSYM)))
        {
            const SHDR& shstr = ELF_STRING_TABLE;
            REDasm::log("Section" + REDasm::quoted(ELF_STRING(&shstr, shdr.sh_name)) + " contains a "
                        "symbol table @ offset " + REDasm::hex(shdr.sh_offset, this->bits()));

            this->loadSymbols(shdr);
        }
    }
}

class Elf32Format: public ElfFormat<ELF_PARAMS(32)>
{
    public:
        Elf32Format(Buffer& buffer);

    protected:
        virtual bool validate() const;
        virtual u64 relocationSymbol(const Elf32_Rel* rel) const;
};

class Elf64Format: public ElfFormat<ELF_PARAMS(64)>
{
    public:
        Elf64Format(Buffer& buffer);

    protected:
        virtual bool validate() const;
        virtual u64 relocationSymbol(const Elf64_Rel* rel) const;
};

DECLARE_FORMAT_PLUGIN(Elf32Format, elf32)
DECLARE_FORMAT_PLUGIN(Elf64Format, elf64)

}

#endif // ELF_H
