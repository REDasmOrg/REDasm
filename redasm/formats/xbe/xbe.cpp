#include "xbe.h"
#include "../../support/ordinals.h"

#define XBE_XBOXKRNL_BASEADDRESS 0x80000000

namespace REDasm {

XbeFormat::XbeFormat(): FormatPluginT<XbeImageHeader>()
{

}

const char *XbeFormat::name() const
{
    return "XBox Executable";
}

u32 XbeFormat::bits() const
{
    return 32;
}

const char *XbeFormat::assembler() const
{
    return "x86_32";
}

bool XbeFormat::load(u8 *rawformat, u64)
{
    XbeImageHeader* format = convert(rawformat);

    if((format->Magic != XBE_MAGIC_NUMBER) || !format->SectionHeader || !format->NumberOfSections)
    {
        if(!format->SectionHeader)
            REDasm::log("Invalid Section Header");
        else if(!format->NumberOfSections)
            REDasm::log("Invalid Number Of Sections");

        return false;
    }

    this->loadSections(this->memoryoffset<XbeSectionHeader>(format->SectionHeader));
    address_t entrypoint = 0;

    if(!this->decodeEP(format->EntryPoint, entrypoint))
    {
        REDasm::log("Cannot decode Entry Point");
        return false;
    }

    if(!this->loadXBoxKrnl())
    {
        REDasm::log("Cannot load XBoxKrnl Imports");
        return false;
    }

    this->defineEntryPoint(entrypoint);
    this->displayXbeInfo();
    FormatPluginT<XbeImageHeader>::load(rawformat);
    return true;
}

void XbeFormat::displayXbeInfo()
{
    XbeCertificate* certificate = this->memoryoffset<XbeCertificate>(this->_format->CertificateAddress);
    std::string title = REDasm::wtoa(&certificate->TitleName, XBE_TITLENAME_SIZE);

    if(!title.empty())
        REDasm::log("Game Title: " + REDasm::quoted(title));

    std::string s;

    if(certificate->GameRegion & XBE_GAME_REGION_RESTOFWORLD)
        s += "ALL";
    else
    {
        if(certificate->GameRegion & XBE_GAME_REGION_JAPAN)
            s += s.empty() ? "JAPAN" : ", JAPAN";

        if(certificate->GameRegion & XBE_GAME_REGION_NA)
            s += s.empty() ? "NORTH AMERICA" : ", NORTH AMERICA";
    }

    if(certificate->GameRegion & XBE_GAME_REGION_MANUFACTURING)
        s += s.empty() ? "DEBUG" : ", DEBUG";

    if(!s.empty())
        REDasm::log("Allowed Regions: " + s);
}

bool XbeFormat::decodeEP(u32 encodedep, address_t& ep)
{
    ep = encodedep ^ XBE_ENTRYPOINT_XOR_RETAIL;
    Segment* segment = this->segment(ep);

    if(!segment)
    {
        ep = encodedep ^ XBE_ENTRYPOINT_XOR_DEBUG;
        segment = this->segment(ep);

        if(segment)
            REDasm::log("Executable Type: DEBUG");
    }
    else
        REDasm::log("Executable Type: RETAIL");

    return segment != NULL;
}

bool XbeFormat::decodeKernel(u32 encodedthunk, u32 &thunk)
{
    thunk = encodedthunk ^ XBE_KERNEL_XOR_RETAIL;
    Segment* segment = this->segment(thunk);

    if(!segment)
    {
        thunk = encodedthunk ^ XBE_KERNEL_XOR_DEBUG;
        segment = this->segment(thunk);
    }

    return segment != NULL;
}

void XbeFormat::loadSections(XbeSectionHeader *sectionhdr)
{
    for(u32 i = 0; i < this->_format->NumberOfSections; i++)
    {
        std::string sectname = this->memoryoffset<const char>(sectionhdr[i].SectionName);
        u32 secttype = SegmentTypes::None;

        if(sectionhdr[i].Flags.Executable)
        {
            if((sectname[0] == '.') && (sectname.find("data") != std::string::npos))
                secttype = SegmentTypes::Data;
            else
                secttype = SegmentTypes::Code;
        }
        else
            secttype = SegmentTypes::Data;

        if(!sectionhdr[i].RawSize)
            secttype = SegmentTypes::Bss;

        this->defineSegment(sectname, sectionhdr[i].RawAddress, sectionhdr[i].VirtualAddress, sectionhdr[i].RawSize, secttype);
    }

    this->defineSegment("XBOXKRNL", 0, XBE_XBOXKRNL_BASEADDRESS, 0x10000, SegmentTypes::Bss);
}

bool XbeFormat::loadXBoxKrnl()
{
    OrdinalsMap ordinals;
    REDasm::loadordinals(REDasm::makeFormatPath("xbe", "xboxkrnl.json"), ordinals);
    u32 kernelimagethunk;

    if(!this->decodeKernel(this->_format->KernelImageThunk, kernelimagethunk))
        return false;

    offset_t thunkoffset = this->offset(kernelimagethunk);
    u32* pthunk = this->pointer<u32>(thunkoffset);

    while(*pthunk)
    {
        std::string ordinalname = REDasm::ordinal(ordinals, *pthunk ^ XBE_ORDINAL_FLAG, "XBoxKrnl!");
        this->defineSymbol(*pthunk, ordinalname, SymbolTypes::Import);
        pthunk++;
    }

    return true;
}

} // namespace REDasm
