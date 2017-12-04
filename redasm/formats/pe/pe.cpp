#include "pe.h"
#include "pe_constants.h"
#include "pe_analyzer.h"
#include "vb/vb_analyzer.h"
#include "../../support/coff/coff_symboltable.h"

namespace REDasm {

PeFormat::PeFormat(): FormatPluginT<ImageDosHeader>(), _dosheader(NULL), _ntheaders(NULL), _sectiontable(NULL), _datadirectory(NULL), _petype(PeType::None), _imagebase(0), _sectionalignment(0), _entrypoint(0)
{

}

const char *PeFormat::name() const
{
    return "PE Format";
}

u32 PeFormat::bits() const
{
    if(this->_ntheaders->OptionalHeaderMagic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
        return 32;

    if(this->_ntheaders->OptionalHeaderMagic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
        return 64;

    return 0;
}

const char *PeFormat::processor() const
{
    if(this->_ntheaders->FileHeader.Machine == IMAGE_FILE_MACHINE_I386)
        return "x86_32";

    if(this->_ntheaders->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64)
        return "x86_64";

    if(this->_ntheaders->FileHeader.Machine == IMAGE_FILE_MACHINE_ARM)
    {
        if(this->_ntheaders->OptionalHeaderMagic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
            return "arm64";

        return "arm";
    }

    return NULL;
}

offset_t PeFormat::offset(address_t address) const
{
    u64 imagebase = (this->_ntheaders->OptionalHeaderMagic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) ? this->_ntheaders->OptionalHeader64.ImageBase :
                                                                                               this->_ntheaders->OptionalHeader32.ImageBase;

    address -= imagebase;
    return this->rvaToOffset(address);
}

Analyzer *PeFormat::createAnalyzer(DisassemblerFunctions *dfunctions) const
{
    if(this->_petype == PeType::VisualBasic)
        return new VBAnalyzer(dfunctions);

    return new PEAnalyzer(dfunctions);
}

bool PeFormat::load(u8 *rawformat)
{
    this->_dosheader = convert(rawformat);

    if(this->_dosheader->e_magic != IMAGE_DOS_SIGNATURE)
        return false;

    this->_ntheaders = reinterpret_cast<ImageNtHeaders*>(rawformat + this->_dosheader->e_lfanew);

    if((this->_ntheaders->Signature != IMAGE_NT_SIGNATURE) || ((this->_ntheaders->OptionalHeaderMagic != IMAGE_NT_OPTIONAL_HDR32_MAGIC) &&
                                                               (this->_ntheaders->OptionalHeaderMagic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)))
        return false;

    this->_sectiontable = IMAGE_FIRST_SECTION(this->_ntheaders);

    if(this->bits() == 64)
    {
        this->_imagebase = this->_ntheaders->OptionalHeader64.ImageBase;
        this->_sectionalignment = this->_ntheaders->OptionalHeader64.SectionAlignment;
        this->_entrypoint = this->_imagebase + this->_ntheaders->OptionalHeader64.AddressOfEntryPoint;
        this->_datadirectory = reinterpret_cast<ImageDataDirectory*>(&this->_ntheaders->OptionalHeader64.DataDirectory);
    }
    else
    {
        this->_imagebase = this->_ntheaders->OptionalHeader32.ImageBase;
        this->_sectionalignment = this->_ntheaders->OptionalHeader32.SectionAlignment;
        this->_entrypoint = this->_imagebase + this->_ntheaders->OptionalHeader32.AddressOfEntryPoint;
        this->_datadirectory = reinterpret_cast<ImageDataDirectory*>(&this->_ntheaders->OptionalHeader32.DataDirectory);
    }

    this->defineEntryPoint(this->_entrypoint);
    this->defineSymbol(this->_imagebase, "PE_ImageBase", SymbolTypes::Data);

    this->loadSections();
    this->loadExports();
    this->loadImports();
    this->loadSymbolTable();

    FormatPluginT<ImageDosHeader>::load(rawformat);
    return true;
}

u64 PeFormat::rvaToOffset(u64 rva, bool *ok) const
{
    for(size_t i = 0; i < this->_ntheaders->FileHeader.NumberOfSections; i++)
    {
        const ImageSectionHeader& section = this->_sectiontable[i];

        if((rva >= section.VirtualAddress) && (rva < (section.VirtualAddress + section.Misc.VirtualSize)))
        {
            if(ok)
                *ok = true;

            return section.PointerToRawData + (rva - section.VirtualAddress);
        }
    }

    return rva;
}

void PeFormat::loadSections()
{
    for(size_t i = 0; i < this->_ntheaders->FileHeader.NumberOfSections; i++)
    {
        const ImageSectionHeader& section = this->_sectiontable[i];
        u64 flags = SegmentTypes::None;

        if((section.Characteristics & IMAGE_SCN_CNT_CODE) || (section.Characteristics & IMAGE_SCN_MEM_EXECUTE))
            flags |= SegmentTypes::Code;

        if((section.Characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA) || (section.Characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA))
            flags |= SegmentTypes::Data;

        if(section.Characteristics & IMAGE_SCN_MEM_READ)
            flags |= SegmentTypes::Read;

        if(section.Characteristics & IMAGE_SCN_MEM_WRITE)
            flags |= SegmentTypes::Write;

        if(!section.SizeOfRawData)
            flags |= SegmentTypes::Bss;

        u64 size = section.Misc.VirtualSize;
        u64 diff = size & this->_sectionalignment;

        if(diff)
            size += this->_sectionalignment - diff;

        std::string name = reinterpret_cast<const char*>(section.Name);

        if(name.empty()) // Rename unnamed sections
            name = "sect" + std::to_string(i);

        this->defineSegment(name, section.PointerToRawData, this->_imagebase + section.VirtualAddress, size, flags);
    }

    Segment* segment = this->segment(this->_entrypoint);

    if(segment) // Entry points always points to code segment
        segment->type |= SegmentTypes::Code;
}

void PeFormat::loadExports()
{
    const ImageDataDirectory& exportdir = this->_datadirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

    if(!exportdir.VirtualAddress)
        return;

    ImageExportDirectory* exporttable = RVA_POINTER(ImageExportDirectory, exportdir.VirtualAddress);
    u32* functions = RVA_POINTER(u32, exporttable->AddressOfFunctions);
    u32* names = RVA_POINTER(u32, exporttable->AddressOfNames);
    u16* nameords = RVA_POINTER(u16, exporttable->AddressOfNameOrdinals);

    for(size_t i = 0; i < exporttable->NumberOfFunctions; i++)
    {
        if(!functions[i])
            continue;

        bool namedfunction = false;
        u32 funcep = this->_imagebase + functions[i];
        const Segment* segment = this->segment(funcep);

        if(!segment)
            continue;

        u32 symboltype = segment->is(SegmentTypes::Code) ? SymbolTypes::ExportFunction :
                                                           SymbolTypes::ExportData;

        for(u64 j = 0; j < exporttable->NumberOfNames; j++)
        {
            if(nameords[j] != i)
                continue;

            namedfunction = true;
            this->defineSymbol(funcep, RVA_POINTER(const char, names[j]), symboltype);
            break;
        }

        if(namedfunction)
            continue;

        std::stringstream ss;
        ss << "Ordinal__" << std::uppercase << std::setw(4) << std::setfill('0') << std::setbase(16) << (exporttable->Base + i);
        this->defineSymbol(funcep, ss.str(), symboltype);
    }
}

void PeFormat::loadImports()
{
    const ImageDataDirectory& importdir = this->_datadirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

    if(!importdir.VirtualAddress)
        return;

    ImageImportDescriptor* importtable = RVA_POINTER(ImageImportDescriptor, importdir.VirtualAddress);

    for(size_t i = 0; i < importtable[i].FirstThunk; i++)
    {
        if(this->bits() == 64)
            this->readDescriptor<ImageThunkData64, static_cast<u64>(IMAGE_ORDINAL_FLAG64)>(importtable[i]);
        else
            this->readDescriptor<ImageThunkData32, static_cast<u64>(IMAGE_ORDINAL_FLAG32)>(importtable[i]);
    }
}

void PeFormat::loadSymbolTable()
{
    if(!this->_ntheaders->FileHeader.PointerToSymbolTable || !this->_ntheaders->FileHeader.NumberOfSymbols)
        return;

    COFF::loadSymbols([this](const std::string& name, COFF::COFF_Entry* entry) {
                      if(this->segmentByName(name)) // Ignore segment informations
                          return;

                      const Segment* segment = this->segmentAt(entry->e_scnum - 1);
                      address_t address = segment->address + entry->e_value;

                      if(segment->is(SegmentTypes::Code))// && (entry->e_sclass == C_EXT))
                          this->defineFunction(address, name);
                      else
                          this->defineSymbol(address, name, SymbolTypes::Data);
    },
    this->pointer<u8>(this->_ntheaders->FileHeader.PointerToSymbolTable),
    this->_ntheaders->FileHeader.NumberOfSymbols);
}

}
