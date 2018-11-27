#include "pe.h"
#include "pe_constants.h"
#include "pe_analyzer.h"
#include "pe_debug.h"
#include "dotnet/dotnet.h"
#include "vb/vb_analyzer.h"
#include "borland/borland_version.h"
#include "../../support/coff/coff_symboltable.h"

namespace REDasm {

PeFormat::PeFormat(Buffer &buffer): FormatPluginT<ImageDosHeader>(buffer), m_dotnetreader(NULL), m_dosheader(NULL), m_ntheaders(NULL), m_sectiontable(NULL), m_datadirectory(NULL), m_petype(PeType::None), m_imagebase(0), m_sectionalignment(0), m_entrypoint(0)
{

}

PeFormat::~PeFormat()
{
    if(m_dotnetreader)
        m_dotnetreader = NULL;
}

const char *PeFormat::name() const { return "PE Format"; }

u32 PeFormat::bits() const
{
    if(m_ntheaders->OptionalHeaderMagic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
        return 32;

    if(m_ntheaders->OptionalHeaderMagic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
        return 64;

    return 0;
}

const char *PeFormat::assembler() const
{
    if(m_petype == PeType::DotNet)
        return "cil";

    if(m_ntheaders->FileHeader.Machine == IMAGE_FILE_MACHINE_I386)
        return "x86_32";

    if(m_ntheaders->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64)
        return "x86_64";

    if(m_ntheaders->FileHeader.Machine == IMAGE_FILE_MACHINE_ARM)
    {
        if(m_ntheaders->OptionalHeaderMagic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
            return "arm64";

        return "arm";
    }

    return NULL;
}

Analyzer *PeFormat::createAnalyzer(DisassemblerAPI *disassembler, const SignatureFiles &signatures) const
{
    if(m_petype == PeType::VisualBasic)
        return new VBAnalyzer(disassembler, signatures);

    return new PEAnalyzer(disassembler, signatures);
}

bool PeFormat::load()
{
    m_dosheader = m_format;

    if(m_dosheader->e_magic != IMAGE_DOS_SIGNATURE)
        return false;

    m_ntheaders = pointer<ImageNtHeaders>(m_dosheader->e_lfanew);

    if((m_ntheaders->Signature != IMAGE_NT_SIGNATURE) || ((m_ntheaders->OptionalHeaderMagic != IMAGE_NT_OPTIONAL_HDR32_MAGIC) &&
                                                          (m_ntheaders->OptionalHeaderMagic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)))
        return false;

    this->m_sectiontable = IMAGE_FIRST_SECTION(m_ntheaders);

    if(this->bits() == 64)
    {
        m_imagebase = m_ntheaders->OptionalHeader64.ImageBase;
        m_sectionalignment = m_ntheaders->OptionalHeader64.SectionAlignment;
        m_entrypoint = m_imagebase + m_ntheaders->OptionalHeader64.AddressOfEntryPoint;
        m_datadirectory = reinterpret_cast<ImageDataDirectory*>(&m_ntheaders->OptionalHeader64.DataDirectory);
    }
    else
    {
        m_imagebase = m_ntheaders->OptionalHeader32.ImageBase;
        m_sectionalignment = m_ntheaders->OptionalHeader32.SectionAlignment;
        m_entrypoint = m_imagebase + m_ntheaders->OptionalHeader32.AddressOfEntryPoint;
        m_datadirectory = reinterpret_cast<ImageDataDirectory*>(&m_ntheaders->OptionalHeader32.DataDirectory);
    }

    ImageCorHeader* corheader = this->checkDotNet();

    if(corheader && (corheader->MajorRuntimeVersion == 1))
    {
        REDasm::log(".NET 1.x is not supported");
        return 0;
    }
    else if(!corheader)
        this->loadDefault();
    else
        this->loadDotNet(reinterpret_cast<ImageCor20Header*>(corheader));

    return true;
}

const DotNetReader *PeFormat::dotNetReader() const { return m_dotnetreader; }

u64 PeFormat::rvaToOffset(u64 rva, bool *ok) const
{
    for(size_t i = 0; i < m_ntheaders->FileHeader.NumberOfSections; i++)
    {
        const ImageSectionHeader& section = m_sectiontable[i];

        if((rva >= section.VirtualAddress) && (rva < (section.VirtualAddress + section.Misc.VirtualSize)))
        {
            if(ok)
                *ok = true;

            return section.PointerToRawData + (rva - section.VirtualAddress);
        }
    }

    return rva;
}

void PeFormat::checkDelphi(const PEResources& peresources)
{
    PEResources::ResourceItem ri = peresources.find(PEResources::RCDATA);

    if(!ri.second)
        return;

    ri = peresources.find("PACKAGEINFO", ri);

    if(!ri.second)
        return;

    u64 datasize = 0;
    PackageInfoHeader* packageinfo = peresources.data<PackageInfoHeader>(ri, this->m_format,
                                                                         [this](address_t a) -> offset_t { return this->rvaToOffset(a); },
                                                                         &datasize);

    BorlandVersion borlandver(packageinfo, ri, datasize);

    if(borlandver.isDelphi())
        m_petype = PeFormat::Delphi;
    else if(borlandver.isTurboCpp())
        m_petype = PeFormat::TurboCpp;

    std::string sig = borlandver.getSignature();

    if(sig.empty())
        return;

    REDasm::log("Signature '" + sig + "' detected");
    m_signatures.push_back(sig);
}

void PeFormat::checkResources()
{
    const ImageDataDirectory& resourcedatadir = m_datadirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE];

    if(!resourcedatadir.VirtualAddress)
        return;

    ImageResourceDirectory* resourcedir = RVA_POINTER(ImageResourceDirectory, resourcedatadir.VirtualAddress);
    PEResources peresources(resourcedir);
    this->checkDelphi(peresources);
}

void PeFormat::checkDebugInfo()
{
    const ImageDataDirectory& debuginfodir = m_datadirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];

    if(!debuginfodir.VirtualAddress)
        return;

    ImageDebugDirectory* debugdir = RVA_POINTER(ImageDebugDirectory, debuginfodir.VirtualAddress);

    if(!debugdir->PointerToRawData)
        return;

    if(debugdir->Type == IMAGE_DEBUG_TYPE_UNKNOWN)
        REDasm::log("Debug info type: UNKNOWN");
    else if(debugdir->Type == IMAGE_DEBUG_TYPE_COFF)
        REDasm::log("Debug info type: COFF");
    else if(debugdir->Type == IMAGE_DEBUG_TYPE_CODEVIEW)
    {
        REDasm::log("Debug info type: CodeView");
        CVHeader* cvhdr = pointer<CVHeader>(debugdir->PointerToRawData);

        if(cvhdr->Signature == PE_PDB_NB10_SIGNATURE)
        {
            CvInfoPDB20* pdb20 = pointer<CvInfoPDB20>(debugdir->PointerToRawData);
            REDasm::log("PDB 2.0 @ " + std::string(reinterpret_cast<const char*>(&pdb20->PdbFileName)));
        }
        else if(cvhdr->Signature == PE_PDB_RSDS_SIGNATURE)
        {
            CvInfoPDB70* pdb70 = pointer<CvInfoPDB70>(debugdir->PointerToRawData);
            REDasm::log("PDB 7.0 @ " + std::string(reinterpret_cast<const char*>(&pdb70->PdbFileName)));
        }
        else
            REDasm::log("Unknown Signature: '" + std::string(reinterpret_cast<const char*>(&cvhdr->Signature), sizeof(u32)));
    }
    else if(debugdir->Type == IMAGE_DEBUG_TYPE_FPO)
        REDasm::log("Debug info type: FPO");
    else if(debugdir->Type == IMAGE_DEBUG_TYPE_MISC)
        REDasm::log("Debug info type: Misc");
    else if(debugdir->Type == IMAGE_DEBUG_TYPE_EXCEPTION)
        REDasm::log("Debug info type: Exception");
    else if(debugdir->Type == IMAGE_DEBUG_TYPE_FIXUP)
        REDasm::log("Debug info type: FixUp");
    else if(debugdir->Type == IMAGE_DEBUG_TYPE_OMAP_TO_SRC)
        REDasm::log("Debug info type: OMAP to Src");
    else if(debugdir->Type == IMAGE_DEBUG_TYPE_OMAP_FROM_SRC)
        REDasm::log("Debug info type: OMAP from Src");
    else if(debugdir->Type == IMAGE_DEBUG_TYPE_BORLAND)
        REDasm::log("Debug info type: Borland");
    else if(debugdir->Type == IMAGE_DEBUG_TYPE_RESERVED10)
        REDasm::log("Debug info type: Reserved10");
    else if(debugdir->Type == IMAGE_DEBUG_TYPE_CLSID)
        REDasm::log("Debug info type: CLSID");
    else
        REDasm::log("Debug info type: " + REDasm::hex(debugdir->Type));

}

ImageCorHeader* PeFormat::checkDotNet()
{
    const ImageDataDirectory& dotnetdir = m_datadirectory[IMAGE_DIRECTORY_ENTRY_DOTNET];

    if(!dotnetdir.VirtualAddress)
        return NULL;

    ImageCorHeader* corheader = RVA_POINTER(ImageCorHeader, dotnetdir.VirtualAddress);

    if(corheader->cb < sizeof(ImageCorHeader))
        return NULL;

    return corheader;
}

void PeFormat::loadDotNet(ImageCor20Header* corheader)
{
    m_petype = PeType::DotNet;

    if(!corheader->MetaData.VirtualAddress)
    {
        REDasm::log("Invalid .NET MetaData");
        return;
    }

    ImageCor20MetaData* cormetadata = RVA_POINTER(ImageCor20MetaData, corheader->MetaData.VirtualAddress);
    m_dotnetreader = new DotNetReader(cormetadata);

    if(!m_dotnetreader->isValid())
        return;

    this->m_dotnetreader->iterateTypes([this](u32 rva, const std::string& name) {
        m_document.function(m_imagebase + rva, name);
    });
}

void PeFormat::loadDefault()
{
    this->loadSections();
    this->loadExports();
    this->loadImports();
    this->loadSymbolTable();
    this->checkDebugInfo();
    this->checkResources();

    m_document.entry(m_entrypoint);
}

void PeFormat::loadSections()
{
    for(size_t i = 0; i < m_ntheaders->FileHeader.NumberOfSections; i++)
    {
        const ImageSectionHeader& section = m_sectiontable[i];
        u32 flags = SegmentTypes::None;

        if((section.Characteristics & IMAGE_SCN_CNT_CODE) || (section.Characteristics & IMAGE_SCN_MEM_EXECUTE))
            flags |= SegmentTypes::Code;

        if((section.Characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA) || (section.Characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA))
            flags |= SegmentTypes::Data;

        if(section.Characteristics & IMAGE_SCN_MEM_READ)
            flags |= SegmentTypes::Read;

        if(section.Characteristics & IMAGE_SCN_MEM_WRITE)
            flags |= SegmentTypes::Write;

        u64 size = section.SizeOfRawData;

        if(!section.SizeOfRawData)
        {
            flags |= SegmentTypes::Bss;
            size = section.Misc.VirtualSize;
        }

        u64 diff = size & m_sectionalignment;

        if(diff)
            size += m_sectionalignment - diff;

        std::string name = reinterpret_cast<const char*>(section.Name);

        if(name.empty()) // Rename unnamed sections
            name = "sect" + std::to_string(i);

        m_document.segment(name, section.PointerToRawData, m_imagebase + section.VirtualAddress, size, flags);
    }

    Segment* segment = m_document.segment(m_entrypoint);

    if(segment) // Entry points always points to code segment
        segment->type |= SegmentTypes::Code;
}

void PeFormat::loadExports()
{
    const ImageDataDirectory& exportdir = m_datadirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

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
        u64 funcep = m_imagebase + functions[i];
        const Segment* segment = m_document.segment(funcep);

        if(!segment)
            continue;

        u32 symboltype = segment->is(SegmentTypes::Code) ? SymbolTypes::ExportFunction :
                                                           SymbolTypes::ExportData;

        for(u64 j = 0; j < exporttable->NumberOfNames; j++)
        {
            if(nameords[j] != i)
                continue;

            namedfunction = true;
            m_document.lock(funcep, RVA_POINTER(const char, names[j]), symboltype);
            break;
        }

        if(namedfunction)
            continue;

        std::stringstream ss;
        ss << "Ordinal__" << std::uppercase << std::setw(4) << std::setfill('0') << std::setbase(16) << (exporttable->Base + i);
        m_document.lock(funcep, ss.str(), symboltype);
    }
}

void PeFormat::loadImports()
{
    const ImageDataDirectory& importdir = m_datadirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

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
    if(!m_ntheaders->FileHeader.PointerToSymbolTable || !m_ntheaders->FileHeader.NumberOfSymbols)
        return;

    REDasm::log("Loading symbol table from " + REDasm::hex(m_ntheaders->FileHeader.PointerToSymbolTable));

    COFF::loadSymbols([this](const std::string& name, COFF::COFF_Entry* entry) {
                      if(m_document.segmentByName(name)) // Ignore segment informations
                          return;

                      const Segment* segment = m_document.segmentAt(entry->e_scnum - 1);
                      address_t address = segment->address + entry->e_value;

                      if(segment->is(SegmentTypes::Code))// && (entry->e_sclass == C_EXT))
                      {
                          m_document.function(address, name);
                          return;
                      }

                      SymbolPtr symbol = m_document.symbol(address);
                      m_document.lock(address, name, symbol ? symbol->type : SymbolTypes::Data,
                                                     symbol ? symbol->tag : 0); // Copy symbol type & tag, if exists
    },

    pointer<u8>(m_ntheaders->FileHeader.PointerToSymbolTable),
    m_ntheaders->FileHeader.NumberOfSymbols);
}

}
