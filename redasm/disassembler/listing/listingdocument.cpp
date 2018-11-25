#include "listingdocument.h"
#include "../../support/utils.h"
#include "../../plugins/format.h"
#include <algorithm>
#include <sstream>

namespace REDasm {

ListingDocument::ListingDocument(): std::deque<ListingItemPtr>(), m_format(NULL) { }
ListingCursor *ListingDocument::cursor() { return &m_cursor; }

void ListingDocument::moveToEP()
{
    if(!m_documententry)
        return;

    m_cursor.set(this->functionIndex(m_documententry->address));
}

u64 ListingDocument::lastLine() const { return static_cast<u64>(this->size()) - 1; }

void ListingDocument::serializeTo(std::fstream &fs)
{
    Serializer::serializeScalar(fs, m_cursor.currentLine());
    Serializer::serializeScalar(fs, m_cursor.currentColumn());

    m_instructions.serializeTo(fs);
    m_symboltable.serializeTo(fs);
}

void ListingDocument::deserializeFrom(std::fstream &fs)
{
    u64 line = 0, column = 0;
    Serializer::deserializeScalar(fs, &line);
    Serializer::deserializeScalar(fs, &column);

    m_instructions.deserialized += [&](const InstructionPtr& instruction) {
        this->pushSorted(instruction->address, ListingItem::InstructionItem);
    };

    m_symboltable.deserialized += [&](const SymbolPtr& symbol) {
        if(symbol->type & SymbolTypes::FunctionMask)
            this->pushSorted(symbol->address, ListingItem::FunctionItem);
        else
            this->pushSorted(symbol->address, ListingItem::SymbolItem);
    };

    m_instructions.deserializeFrom(fs);
    m_symboltable.deserializeFrom(fs);

    m_instructions.deserialized.removeLast();
    m_symboltable.deserialized.removeLast();

    m_cursor.set(line, column);
}

ListingItems ListingDocument::getCalls(ListingItem *item)
{
    ListingItems calls;
    ListingDocument::iterator it = this->end();

    if(item->is(ListingItem::InstructionItem))
    {
        InstructionPtr instruction = this->instruction(item->address);

        if(!instruction->hasTargets())
            return ListingItems();

        it = this->instructionItem(instruction->target());
    }
    else
        it = this->instructionItem(item->address);

    for( ; it != this->end(); it++)
    {
        ListingItem* item = it->get();

        if(item->is(ListingItem::InstructionItem))
        {
            InstructionPtr instruction = this->instruction(item->address);

            if(!instruction->is(InstructionTypes::Call))
                continue;

            calls.push_back(item);
        }
        else if(item->is(ListingItem::SymbolItem))
        {
            SymbolPtr symbol = this->symbol(item->address);

            if(!symbol->is(SymbolTypes::Code))
                break;
        }
        else
            break;
    }

    return calls;
}

ListingItem *ListingDocument::functionStart(ListingItem *item) { return this->functionStart(item->address); }

ListingItem *ListingDocument::functionStart(address_t address)
{
    auto iit = this->instructionItem(address);

    if(iit == this->end())
        return NULL;

    document_lock lock(m_mutex);
    auto fit = std::lower_bound(m_functions.begin(), m_functions.end(), iit->get(), Listing::ListingComparator<ListingItem*>());

    if(fit == m_functions.end())
        return NULL;

    if(fit != m_functions.begin())
        fit--;

    return *fit;
}

ListingItem *ListingDocument::currentItem()
{
    if(m_cursor.currentLine() >= static_cast<u64>(this->size()))
        return NULL;

    return this->itemAt(m_cursor.currentLine());
}

SymbolPtr ListingDocument::functionStartSymbol(address_t address)
{
    ListingItem* item = this->functionStart(address);

    if(item)
        return this->symbol(item->address);

    return NULL;
}

std::string ListingDocument::comment(address_t address) const
{
    auto it = m_comments.find(address);

    if(it == m_comments.end())
        return std::string();

    std::string cmt;

    for(const std::string& s : it->second)
    {
        if(!cmt.empty())
            cmt += " | ";

        cmt += s;
    }

    return cmt;
}

void ListingDocument::comment(address_t address, const std::string &s)
{
    auto it = m_comments.find(address);

    if(it != m_comments.end())
    {
        it->second.insert(s);
        return;
    }

    CommentSet cs;
    cs.insert(s);
    m_comments[address] = cs;
}

void ListingDocument::symbol(address_t address, const std::string &name, u32 type, u32 tag)
{
    SymbolPtr symbol = m_symboltable.symbol(address);

    if(symbol)
    {
        if(symbol->isLocked() && !(type & SymbolTypes::Locked))
            return;

        if(symbol->isFunction())
            this->removeSorted(address, ListingItem::FunctionItem);
        else
            this->removeSorted(address, ListingItem::SymbolItem);

        m_symboltable.erase(address);
    }

    if(!this->segment(address) || !m_symboltable.create(address, ListingDocument::normalized(name), type, tag))
        return;

    if(type & SymbolTypes::FunctionMask)
        this->pushSorted(address, ListingItem::FunctionItem);
    else
        this->pushSorted(address, ListingItem::SymbolItem);
}

void ListingDocument::symbol(address_t address, u32 type, u32 tag)
{
    if(type & SymbolTypes::TableMask)
        this->symbol(address, this->symbolName("tbl", address), type, tag);
    else if(type & SymbolTypes::Pointer)
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

void ListingDocument::rename(address_t address, const std::string &name)
{
    if(name.empty())
        return;

    SymbolPtr symbol = this->symbol(address);

    if(!symbol)
        return;

    this->symbol(address, name, symbol->type, symbol->tag);
}

void ListingDocument::lock(address_t address, const std::string &name)
{
    SymbolPtr symbol = m_symboltable.symbol(address);

    if(!symbol)
        this->lock(address, name.empty() ? symbol->name : name, SymbolTypes::Data);
    else
        this->lock(address, name.empty() ? symbol->name : name, symbol->type, symbol->tag);
}

void ListingDocument::lock(address_t address, u32 type, u32 tag) { this->symbol(address, type | SymbolTypes::Locked, tag); }
void ListingDocument::lock(address_t address, const std::string &name, u32 type, u32 tag) { this->symbol(address, name, type | SymbolTypes::Locked, tag); }

void ListingDocument::segment(const std::string &name, offset_t offset, address_t address, u64 size, u32 type)
{
    Segment segment(name, offset, address, size, type);

    auto it = std::lower_bound(m_segments.begin(), m_segments.end(), segment, [](const Segment& s1, const Segment& s2) -> bool {
        return s1.address < s2.address;
    });

    it = m_segments.insert(it, segment);
    this->pushSorted(address, ListingItem::SegmentItem);
}

void ListingDocument::function(address_t address, const std::string &name, u32 tag) { this->lock(address, name, SymbolTypes::Function, tag); }
void ListingDocument::function(address_t address, u32 tag) { this->symbol(address, SymbolTypes::Function, tag); }
void ListingDocument::pointer(address_t address, u32 type, u32 tag) { this->symbol(address, type | SymbolTypes::Pointer, tag); }
void ListingDocument::table(address_t address, u32 tag) { this->lock(address, SymbolTypes::Table, tag); }

void ListingDocument::entry(address_t address, u32 tag)
{
    this->lock(address, ENTRYPOINT_FUNCTION, SymbolTypes::EntryPoint, tag);
    this->setDocumentEntry(address);
}

void ListingDocument::eraseSymbol(address_t address)
{
    this->removeSorted(address, ListingItem::SymbolItem);
    m_symboltable.erase(address);
}

void ListingDocument::setDocumentEntry(address_t address)
{
    m_documententry = m_symboltable.symbol(address);
    m_cursor.set(this->functionIndex(address));
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

ListingDocument::iterator ListingDocument::functionItem(address_t address) { return this->item(address, ListingItem::FunctionItem); }

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

std::string ListingDocument::normalized(std::string s)
{
    std::replace(s.begin(), s.end(), '.', '_');
    std::replace(s.begin(), s.end(), ' ', '_');
    return s;
}

ListingDocument::iterator ListingDocument::instructionItem(address_t address) { return this->item(address, ListingItem::InstructionItem); }
ListingDocument::iterator ListingDocument::symbolItem(address_t address) { return this->item(address, ListingItem::SymbolItem); }

ListingDocument::iterator ListingDocument::item(address_t address)
{
    auto it = this->symbolItem(address);

    if(it == this->end())
        it = this->instructionItem(address);

    return it;
}

int ListingDocument::functionIndex(address_t address) { return this->index(address, ListingItem::FunctionItem); }
int ListingDocument::instructionIndex(address_t address) { return this->index(address, ListingItem::InstructionItem); }
int ListingDocument::symbolIndex(address_t address) { return this->index(address, ListingItem::SymbolItem); }

ListingItem* ListingDocument::itemAt(size_t i)
{
    document_lock lock(m_mutex);
    return this->at(i).get();
}

int ListingDocument::indexOf(address_t address)
{
    int idx = this->symbolIndex(address);

    if(idx == -1)
        idx = this->instructionIndex(address);

    return idx;
}

int ListingDocument::indexOf(ListingItem *item)
{
    document_lock lock(m_mutex);
    return Listing::indexOf(this, item);
}

SymbolPtr ListingDocument::symbol(address_t address) { return m_symboltable.symbol(address); }
SymbolPtr ListingDocument::symbol(const std::string &name) { return m_symboltable.symbol(ListingDocument::normalized(name)); }
SymbolTable *ListingDocument::symbols() { return &m_symboltable; }
InstructionCache *ListingDocument::instructions() { return &m_instructions; }
FormatPlugin *ListingDocument::format() { return m_format; }

void ListingDocument::pushSorted(address_t address, u32 type)
{
    document_lock lock(m_mutex);
    ListingItemPtr itemptr = std::make_unique<ListingItem>(address, type);

    if(type == ListingItem::FunctionItem)
    {
        auto it = Listing::insertionPoint(&m_functions, itemptr.get());
        m_functions.insert(it, itemptr.get());
    }

    auto it = Listing::insertionPoint(this, itemptr);

    if((it != this->end()) && (((*it)->address == address) && ((*it)->type == type)))
        return;

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

    if(type == ListingItem::FunctionItem)
    {
        auto it = Listing::binarySearch(&m_functions, address, type);
        m_functions.erase(it);
    }

    this->erase(it);
}

std::string ListingDocument::symbolName(const std::string &prefix, address_t address, const Segment *segment)
{
    std::stringstream ss;
    ss << prefix;

    if(segment)
        ss << "_" << ListingDocument::normalized(segment->name);

    ss << "_" << std::hex << address;
    return ss.str();
}

} // namespace REDasm
