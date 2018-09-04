#ifndef LISTINGDOCUMENT_H
#define LISTINGDOCUMENT_H

#include <vector>
#include "../../redasm.h"
#include "../types/symboltable.h"
#include "../types/referencetable.h"
#include "instructionpool.h"

namespace REDasm {

class FormatPlugin;

struct ListingItem
{
    enum: u32 {
        Undefined = 0,
        DataItem      = 1,
        SegmentItem   = 2, FunctionItem = 3, InstructionItem = 4,
    };

    ListingItem(): address(0), type(ListingItem::Undefined) { }
    ListingItem(address_t address, u32 type): address(address), type(type) { }
    bool is(u32 t) const { return type == t; }

    address_t address;
    u32 type;
};

class ListingDocument
{
    public:
        ListingDocument();
        void symbol(address_t address, const std::string& name, u32 type, u32 tag = 0);
        void lock(address_t address, const std::string& name, u32 type, u32 tag = 0);
        void segment(const std::string& name, offset_t offset, address_t address, u64 size, u32 type);
        void function(address_t address, const std::string& name, u32 tag = 0);
        void function(address_t address, u32 tag = 0);
        void entry(address_t address, u32 tag = 0);
        void sort();

    public:
        const SegmentList& segments() const;
        Segment *segment(address_t address);
        Segment *segmentAt(size_t idx);
        Segment *segmentByName(const std::string& name);

    public:
        size_t count() const;
        ListingItem &at(size_t i);
        SymbolTable* symbols();
        FormatPlugin* format();

    private:
        std::vector<ListingItem> m_items;
        SegmentList m_segments;
        InstructionPool m_instructions;
        SymbolTable m_symboltable;
        FormatPlugin* m_format;

     friend class FormatPlugin;
};

} // namespace REDasm

#endif // ITEMDOCUMENT_H
