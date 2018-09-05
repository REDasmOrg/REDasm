#include "listingdocument.h"
#include <algorithm>

namespace REDasm {

ListingDocument::ListingDocument(): m_format(NULL) { }
void ListingDocument::whenChanged(const ListingDocument::ChangedCallback &cb) { m_changedcb = cb; }

void ListingDocument::symbol(address_t address, const std::string &name, u32 type, u32 tag)
{
    if(!m_symboltable.create(address, name, type, tag))
        return;

    if(type & SymbolTypes::Function)
        this->pushSorted(ListingItem(address, ListingItem::FunctionItem));
}

void ListingDocument::symbol(address_t address, u32 type, u32 tag)
{
    if(type & SymbolTypes::Pointer)
        this->symbol(address, this->symbolName("ptr", address), type, tag);
    else if(type & SymbolTypes::WideString)
        this->symbol(address, this->symbolName("wstr", address), type, tag);
    else if(type & SymbolTypes::String)
        this->symbol(address, this->symbolName("str", address), type, tag);
    else if(type & SymbolTypes::Function)
        this->symbol(address, this->symbolName("sub", address), type, tag);
    else
    {
        const Segment* segment = this->segment(address);

        if(segment && segment->is(SegmentTypes::Code))
            this->symbol(address, this->symbolName("loc", address), type, tag);
        else
            this->symbol(address, this->symbolName("data", address), type, tag);
    }
}

void ListingDocument::lock(address_t address, const std::string &name, u32 type, u32 tag)
{
    this->symbol(address, name, type | SymbolTypes::Locked, tag);
}

void ListingDocument::segment(const std::string &name, offset_t offset, address_t address, u64 size, u32 type)
{
    m_segments.push_back(Segment(name, offset, address, size, type));
    this->pushSorted(ListingItem(address, ListingItem::SegmentItem));
}

void ListingDocument::function(address_t address, const std::string &name, u32 tag) { this->lock(address, name, SymbolTypes::Function, tag); }
void ListingDocument::function(address_t address, u32 tag) { this->symbol(address, REDasm::symbol("sub", address), SymbolTypes::Function, tag); }
void ListingDocument::entry(address_t address, u32 tag) { this->symbol(address, ENTRYPOINT_FUNCTION, SymbolTypes::EntryPoint, tag); }

void ListingDocument::sort()
{
    std::sort(m_segments.begin(), m_segments.end(), [](const Segment& s1, const Segment& s2) -> bool {
        return s1.address < s2.address;
    });
}

size_t ListingDocument::segmentsCount() const { return m_segments.size(); }

Segment *ListingDocument::segment(address_t address)
{
    for(auto it = m_segments.begin(); it != m_segments.end(); it++)
    {
        if(it->contains(address))
            return &(*it);
    }

    return NULL;
}

const Segment *ListingDocument::segment(address_t address) const { return const_cast<ListingDocument*>(this)->segment(address); }
const Segment *ListingDocument::segmentAt(size_t idx) const { return &m_segments[idx]; }

const Segment *ListingDocument::segmentByName(const std::string &name) const
{
    for(auto it = m_segments.begin(); it != m_segments.end(); it++)
    {
        const Segment& segment = *it;

        if(segment.name == name)
            return &segment;
    }

    return NULL;
}

void ListingDocument::instruction(const InstructionPtr &instruction)
{
    m_instructions.commit(instruction->address, instruction);
    this->pushSorted(ListingItem(instruction->address, ListingItem::InstructionItem));
}

InstructionPtr ListingDocument::instruction(address_t address)
{
    auto it = m_instructions.find(address);

    if(it != m_instructions.end())
        return *it;

    return InstructionPtr();
}

size_t ListingDocument::count() const { return m_items.size(); }
ListingItem* ListingDocument::at(size_t i) { return m_items[i].get(); }
SymbolPtr ListingDocument::symbol(address_t address) { return m_symboltable.symbol(address); }
SymbolTable *ListingDocument::symbols() { return &m_symboltable; }
FormatPlugin *ListingDocument::format() { return m_format; }

void ListingDocument::pushSorted(const ListingItem &item)
{
    ListingItemPtr itemptr = std::make_unique<ListingItem>(item);

    auto it = std::lower_bound(m_items.begin(), m_items.end(), itemptr, [this](const ListingItemPtr& b1, const ListingItemPtr& b2) {
        if(b1->address == b2->address)
            return b1->type < b2->type;

        return b1->address < b2->address;
    });

    m_items.insert(it, std::move(itemptr));

    if(!m_changedcb)
        return;

    size_t idx = std::distance(m_items.begin(), it);
    m_changedcb(idx);
}

std::string ListingDocument::symbolName(const std::string &prefix, address_t address, const Segment *segment)
{
    std::stringstream ss;
    ss << prefix;

    if(segment)
        ss << "_" << REDasm::normalize(segment->name);

    ss << "_" << std::hex << address;
    return ss.str();
}

} // namespace REDasm
