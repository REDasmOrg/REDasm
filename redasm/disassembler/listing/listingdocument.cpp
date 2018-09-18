#include "listingdocument.h"
#include <algorithm>
#include <sstream>

namespace REDasm {

ListingDocument::ListingDocument(): std::vector<ListingItemPtr>(), m_format(NULL) { }
ListingCursor *ListingDocument::cursor() { return &m_cursor; }

void ListingDocument::symbol(address_t address, const std::string &name, u32 type, u32 tag)
{
    SymbolPtr symbol = m_symboltable.symbol(address);

    if(symbol)
    {
        if(symbol->isLocked() || !(type & SymbolTypes::Locked))
            return;

        if(type & SymbolTypes::FunctionMask)
            this->removeSorted(address, ListingItem::FunctionItem);
        else
            this->removeSorted(address, ListingItem::SymbolItem);

        m_symboltable.erase(address);
    }

    if(!this->segment(address) || !m_symboltable.create(address, name, type, tag))
        return;

    if(type & SymbolTypes::FunctionMask)
        this->pushSorted(address, ListingItem::FunctionItem);
    else
        this->pushSorted(address, ListingItem::SymbolItem);
}

void ListingDocument::symbol(address_t address, u32 type, u32 tag)
{
    if(type & SymbolTypes::Pointer)
        this->symbol(address, this->symbolName("ptr", address), type, tag);
    else if(type & SymbolTypes::WideStringMask)
        this->symbol(address, this->symbolName("wstr", address), type, tag);
    else if(type & SymbolTypes::StringMask)
        this->symbol(address, this->symbolName("str", address), type, tag);
    else if(type & SymbolTypes::FunctionMask)
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

void ListingDocument::lock(address_t address, const std::string &name)
{
    SymbolPtr symbol = m_symboltable.symbol(address);

    if(!symbol)
        this->lock(address, name, SymbolTypes::Data);
    else
        this->lock(address, name, symbol->type, symbol->tag);
}

void ListingDocument::lock(address_t address, const std::string &name, u32 type, u32 tag)
{
    this->symbol(address, name, type | SymbolTypes::Locked, tag);
}

void ListingDocument::segment(const std::string &name, offset_t offset, address_t address, u64 size, u32 type)
{
    Segment segment(name, offset, address, size, type);

    auto it = std::lower_bound(m_segments.begin(), m_segments.end(), segment, [](const Segment& s1, const Segment& s2) -> bool {
        return s1.address < s2.address;
    });

    it = m_segments.insert(it, segment);
    this->pushSorted(address, ListingItem::SegmentItem);
    segmentadded(std::distance(m_segments.begin(), it));
}

void ListingDocument::function(address_t address, const std::string &name, u32 tag) { this->lock(address, name, SymbolTypes::Function, tag); }
void ListingDocument::function(address_t address, u32 tag) { this->symbol(address, ListingDocument::symbolName("sub", address), SymbolTypes::Function, tag); }

void ListingDocument::entry(address_t address, u32 tag)
{
    this->lock(address, ENTRYPOINT_FUNCTION, SymbolTypes::EntryPoint, tag);
    this->setDocumentEntry(address);
}

void ListingDocument::setDocumentEntry(address_t address)
{
    m_documententry = m_symboltable.symbol(address);
    m_cursor.moveTo(this->functionIndex(address));
}

SymbolPtr ListingDocument::documentEntry() const { return m_documententry; }
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
    this->pushSorted(instruction->address, ListingItem::InstructionItem);
}

void ListingDocument::update(const InstructionPtr &instruction) { m_instructions.update(instruction); }

InstructionPtr ListingDocument::instruction(address_t address)
{
    document_lock lock(m_mutex);
    auto it = m_instructions.find(address);

    if(it != m_instructions.end())
        return *it;

    return InstructionPtr();
}

ListingDocument::iterator ListingDocument::item(address_t address, u32 type)
{
    document_lock lock(m_mutex);
    return Listing::binarySearch(this, address, type);
}

int ListingDocument::index(address_t address, u32 type)
{
    document_lock lock(m_mutex);
    return Listing::indexOf(this, address, type);
}

ListingDocument::iterator ListingDocument::instructionItem(address_t address) { return this->item(address, ListingItem::InstructionItem); }
ListingDocument::iterator ListingDocument::symbolItem(address_t address) { return this->item(address, ListingItem::SymbolItem); }
int ListingDocument::functionIndex(address_t address) { return this->index(address, ListingItem::FunctionItem); }
int ListingDocument::instructionIndex(address_t address) { return this->index(address, ListingItem::InstructionItem); }

ListingItem* ListingDocument::itemAt(size_t i)
{
    document_lock lock(m_mutex);
    return this->at(i).get();
}

int ListingDocument::indexOf(ListingItem *item)
{
    document_lock lock(m_mutex);
    return Listing::indexOf(this, item);
}

SymbolPtr ListingDocument::symbol(address_t address) { return m_symboltable.symbol(address); }
SymbolPtr ListingDocument::symbol(const std::string &name) { return m_symboltable.symbol(name); }
SymbolTable *ListingDocument::symbols() { return &m_symboltable; }
FormatPlugin *ListingDocument::format() { return m_format; }

void ListingDocument::pushSorted(address_t address, u32 type)
{
    document_lock lock(m_mutex);
    ListingItemPtr itemptr = std::make_unique<ListingItem>(address, type);

    auto it = Listing::insertionPoint(this, itemptr);
    it = this->insert(it, std::move(itemptr));
    ListingDocumentChanged ldc(it->get(), std::distance(this->begin(), it), false);
    changed(&ldc);
}

void ListingDocument::removeSorted(address_t address, u32 type)
{
    document_lock lock(m_mutex);
    auto it = Listing::binarySearch(this, address, type);

    if(it == this->end())
        return;

    ListingDocumentChanged ldc(it->get(), std::distance(this->begin(), it), true);
    changed(&ldc);
    this->erase(it);
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
