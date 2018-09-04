#include "listingdocument.h"
#include <algorithm>

namespace REDasm {

ListingDocument::ListingDocument(): m_format(NULL) { }

void ListingDocument::symbol(address_t address, const std::string &name, u32 type, u32 tag)
{
    m_symboltable.create(address, name, type, tag);

    if(type & SymbolTypes::Function)
        m_items.push_back(ListingItem(address, ListingItem::FunctionItem));

}

void ListingDocument::lock(address_t address, const std::string &name, u32 type, u32 tag)
{
    this->symbol(address, name, type | SymbolTypes::Locked, tag);
}

void ListingDocument::segment(const std::string &name, offset_t offset, address_t address, u64 size, u32 type)
{
    m_segments.push_back(Segment(name, offset, address, size, type));
    m_items.push_back(ListingItem(address, ListingItem::SegmentItem));
}

void ListingDocument::function(address_t address, const std::string &name, u32 tag) { this->lock(address, name, SymbolTypes::Function, tag); }
void ListingDocument::function(address_t address, u32 tag) { this->symbol(address, REDasm::symbol("sub", address), SymbolTypes::Function, tag); }
void ListingDocument::entry(address_t address, u32 tag) { this->symbol(address, ENTRYPOINT_FUNCTION, SymbolTypes::EntryPoint, tag); }

void ListingDocument::sort()
{
    std::sort(m_segments.begin(), m_segments.end(), [](const Segment& s1, const Segment& s2) -> bool {
        return s1.address < s2.address;
    });

    std::sort(m_items.begin(), m_items.end(), [this](const ListingItem& b1, const ListingItem& b2) {
        if(b1.address == b2.address)
            return b1.type < b2.type;

        return b1.address < b2.address;
    });
}

const SegmentList &ListingDocument::segments() const { return m_segments; }

Segment *ListingDocument::segment(address_t address)
{
    for(auto it = m_segments.begin(); it != m_segments.end(); it++)
    {
        if(it->contains(address))
            return &(*it);
    }

    return NULL;
}

Segment *ListingDocument::segmentAt(size_t idx) { return &m_segments[idx]; }

Segment *ListingDocument::segmentByName(const std::string &name)
{
    for(auto it = m_segments.begin(); it != m_segments.end(); it++)
    {
        Segment& segment = *it;

        if(segment.name == name)
            return &segment;
    }

    return NULL;
}

size_t ListingDocument::count() const { return m_items.size(); }
ListingItem& ListingDocument::at(size_t i) { return m_items.at(i); }
SymbolTable *ListingDocument::symbols() { return &m_symboltable; }
FormatPlugin *ListingDocument::format() { return m_format; }

} // namespace REDasm
