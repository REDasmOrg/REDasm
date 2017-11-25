#include "format.h"

namespace REDasm {

FormatPlugin::FormatPlugin(): Plugin()
{

}

const SegmentVector &FormatPlugin::segments() const
{
    return _segments;
}

const SymbolTable &FormatPlugin::symbols() const
{
    return this->_symbol;
}

Segment *FormatPlugin::segment(address_t address)
{
    for(auto it = this->_segments.begin(); it != this->_segments.end(); it++)
    {
        if(it->contains(address))
            return &(*it);
    }

    return NULL;
}

offset_t FormatPlugin::offset(address_t address) const
{
    for(auto it = this->_segments.begin(); it != this->_segments.end(); it++)
    {
        const Segment& segment = *it;

        if(segment.contains(address))
            return (address - segment.address) + segment.offset;
    }

    return address;
}

Analyzer* FormatPlugin::createAnalyzer() const
{
    return new Analyzer();
}

bool FormatPlugin::load(u8 *format)
{
    RE_UNUSED(format);

    std::sort(this->_segments.begin(), this->_segments.end(), [](const Segment& s1, const Segment& s2) -> bool {
        return s1.address < s2.address;
    });

    return false;
}

void FormatPlugin::defineSegment(const std::string &name, offset_t offset, address_t address, u64 size, u32 flags)
{
    this->_segments.push_back(Segment(name, offset, address, size, flags));
}

void FormatPlugin::defineSymbol(address_t address, const std::string &name, u32 flags)
{
    this->_symbol.create(address, name, flags | SymbolTypes::Locked);
}

void FormatPlugin::defineFunction(address_t address, const std::string& name)
{
    this->defineSymbol(address, name, SymbolTypes::Function);
}

void FormatPlugin::defineEntryPoint(address_t address)
{
    this->defineSymbol(address, ENTRYPOINT_FUNCTION, SymbolTypes::EntryPoint);
}

}
