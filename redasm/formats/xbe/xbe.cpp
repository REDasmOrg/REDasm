#include "xbe.h"

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

bool XbeFormat::load(u8 *rawformat)
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

    this->defineEntryPoint(entrypoint);
    FormatPluginT<XbeImageHeader>::load(rawformat);
    return true;
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
            REDasm::log("DEBUG Executable");
    }
    else
        REDasm::log("RETAIL Executable");

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
}

} // namespace REDasm
