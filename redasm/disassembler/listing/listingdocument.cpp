#include "listingdocument.h"
#include <algorithm>

namespace REDasm {

ListingDocument::ListingDocument() { }

void ListingDocument::add(Segment segment)
{
    m_segments.push_back(segment);
    m_items.push_back(ListingItem(segment.address, ListingItem::SegmentItem));
}

void ListingDocument::add(address_t address, const std::string &name, u32 type)
{
    m_symboltable.create(address, name, type);

    if(type & SymbolTypes::Function)
        m_items.push_back(ListingItem(address, ListingItem::FunctionItem));

}

void ListingDocument::add(const ListingItem &block) { m_items.push_back(block); }
void ListingDocument::entry(address_t address) { this->add(address, ENTRYPOINT_FUNCTION, SymbolTypes::EntryPoint); }

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

} // namespace REDasm
