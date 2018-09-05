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
        DataItem,
        SegmentItem, FunctionItem, PrologueItem, InstructionItem,
    };

    ListingItem(): address(0), type(ListingItem::Undefined) { }
    ListingItem(address_t address, u32 type): address(address), type(type) { }
    bool is(u32 t) const { return type == t; }

    address_t address;
    u32 type;
};

class ListingDocument
{
    private:
        typedef std::function<void(int)> ChangedCallback;
        typedef std::unique_ptr<ListingItem> ListingItemPtr;

    public:
        ListingDocument();
        void whenChanged(const ChangedCallback& cb);
        void symbol(address_t address, const std::string& name, u32 type, u32 tag = 0);
        void symbol(address_t address, u32 type, u32 tag = 0);
        void lock(address_t address, const std::string& name, u32 type, u32 tag = 0);
        void segment(const std::string& name, offset_t offset, address_t address, u64 size, u32 type);
        void function(address_t address, const std::string& name, u32 tag = 0);
        void function(address_t address, u32 tag = 0);
        void entry(address_t address, u32 tag = 0);
        void sort();

    public:
        size_t segmentsCount() const;
        Segment *segment(address_t address);
        const Segment *segment(address_t address) const;
        const Segment *segmentAt(size_t idx) const;
        const Segment *segmentByName(const std::string& name) const;

    public:
        void instruction(const InstructionPtr& instruction);
        InstructionPtr instruction(address_t address);

    public:
        size_t count() const;
        ListingItem* at(size_t i);
        SymbolPtr symbol(address_t address);
        SymbolTable* symbols();
        FormatPlugin* format();

    private:
        void pushSorted(const ListingItem& item);
        static std::string symbolName(const std::string& prefix, address_t address, const Segment* segment = NULL);

    private:
        std::vector<ListingItemPtr> m_items;
        SegmentList m_segments;
        InstructionPool m_instructions;
        SymbolTable m_symboltable;
        FormatPlugin* m_format;
        ChangedCallback m_changedcb;

     friend class FormatPlugin;
};

} // namespace REDasm

#endif // ITEMDOCUMENT_H
