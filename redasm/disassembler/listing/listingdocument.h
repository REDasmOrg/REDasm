#ifndef LISTINGDOCUMENT_H
#define LISTINGDOCUMENT_H

#include <unordered_set>
#include <type_traits>
#include <vector>
#include <list>
#include "../../redasm.h"
#include "../../support/event.h"
#include "../../support/serializer.h"
#include "../types/symboltable.h"
#include "../types/referencetable.h"
#include "listingcursor.h"
#include "instructioncache.h"

namespace REDasm {

class FormatPlugin;

struct ListingItem
{
    enum: u32 {
        Undefined = 0,
        SegmentItem, FunctionItem, PrologueItem, SymbolItem, InstructionItem,
        AllItems = static_cast<u32>(-1)
    };

    ListingItem(): address(0), type(ListingItem::Undefined) { }
    ListingItem(address_t address, u32 type): address(address), type(type) { }
    bool is(u32 t) const { return type == t; }

    address_t address;
    u32 type;
};

typedef std::unique_ptr<ListingItem> ListingItemPtr;
typedef std::vector<ListingItem*> ListingItems;

namespace Listing {
    template<typename T> struct ListingComparator {
        bool operator()(const T& t1, const T& t2) {
            if(t1->address == t2->address)
                return t1->type < t2->type;

            return t1->address < t2->address;
        }
    };

    template<typename T> struct IteratorSelector {
        typedef typename std::conditional<std::is_const<T>::value, typename T::const_iterator, typename T::iterator>::type Type;
    };

    template<typename T, typename V, typename IT = typename IteratorSelector<T>::Type> typename T::iterator insertionPoint(T* container, const V& item) {
        return std::lower_bound(container->begin(), container->end(), item, ListingComparator<V>());
    }

    template<typename T, typename IT = typename IteratorSelector<T>::Type> IT _adjustSearch(T* container, IT it, u32 type) {
        int offset = type - (*it)->type;
        address_t searchaddress = (*it)->address;

        while((it != container->end()) && (searchaddress == (*it)->address))
        {
            if((*it)->type == type)
                return it;

            if((offset < 0) && (it == container->begin()))
                break;

            offset > 0 ? it++ : it--;
        }

        return container->end();
    }

    template<typename T, typename IT = typename IteratorSelector<T>::Type> IT binarySearch(T* container, address_t address, u32 type) {
        if(!container->size())
            return container->end();

        auto thebegin = container->begin(), theend = container->end();

        while(thebegin <= theend)
        {
            auto range = std::distance(thebegin, theend);
            auto themiddle = thebegin;
            std::advance(themiddle, range / 2);

            if((*themiddle)->address == address)
                return Listing::_adjustSearch(container, themiddle, type);

            if((*themiddle)->address > address)
            {
                theend = themiddle;
                std::advance(theend, -1);
            }
            else if((*themiddle)->address < address)
            {
                thebegin = themiddle;
                std::advance(thebegin, 1);
            }
        }

        return container->end();
    }

    template<typename T, typename V, typename IT = typename IteratorSelector<T>::Type> IT binarySearch(T* container, V* item) {
        return Listing::binarySearch(container, item->address, item->type);
    }

    template<typename T, typename V, typename IT = typename IteratorSelector<T>::Type> int indexOf(T* container, V* item) {
        auto it = Listing::binarySearch(container, item);

        if(it == container->end())
            return -1;

        return std::distance(container->begin(), it);
    }

    template<typename T, typename IT = typename IteratorSelector<T>::Type> int indexOf(T* container, address_t address, u32 type) {
        auto it = Listing::binarySearch(container, address, type);

        if(it == container->end())
            return -1;

        return std::distance(container->begin(), it);
    }
}

struct ListingDocumentChanged
{
    ListingDocumentChanged(ListingItem* item, u64 index, bool removed): item(item), index(index), removed(removed) { }

    ListingItem* item;

    u64 index;
    bool removed;
};

class ListingDocument: protected std::deque<ListingItemPtr>, public Serializer::Serializable
{
    using document_lock = std::unique_lock<std::mutex>;

    public:
        Event<const ListingDocumentChanged*> changed;

    private:
        typedef std::unordered_set<std::string> CommentSet;
        typedef std::unordered_map<address_t, CommentSet> CommentMap;
        typedef std::deque<ListingItem*> FunctionList;

    public:
        using std::deque<ListingItemPtr>::const_iterator;
        using std::deque<ListingItemPtr>::iterator;
        using std::deque<ListingItemPtr>::begin;
        using std::deque<ListingItemPtr>::end;
        using std::deque<ListingItemPtr>::size;

    public:
        ListingDocument();
        ListingCursor* cursor();
        void moveToEP();
        u64 lastLine() const;

    public:
        virtual void serializeTo(std::fstream& fs);
        virtual void deserializeFrom(std::fstream& fs);

    public:
        ListingItems getCalls(ListingItem* item);
        ListingItem* functionStart(ListingItem* item);
        ListingItem* functionStart(address_t address);
        ListingItem* currentItem();
        SymbolPtr functionStartSymbol(address_t address);
        std::string comment(address_t address) const;
        void comment(address_t address, const std::string& s);
        void symbol(address_t address, const std::string& name, u32 type, u32 tag = 0);
        void symbol(address_t address, u32 type, u32 tag = 0);
        void rename(address_t address, const std::string& name);
        void lock(address_t address, const std::string& name);
        void lock(address_t address, u32 type, u32 tag = 0);
        void lock(address_t address, const std::string& name, u32 type, u32 tag = 0);
        void segment(const std::string& name, offset_t offset, address_t address, u64 size, u32 type);
        void function(address_t address, const std::string& name, u32 tag = 0);
        void function(address_t address, u32 tag = 0);
        void pointer(address_t address, u32 type, u32 tag = 0);
        void table(address_t address, u32 tag = 0);
        void entry(address_t address, u32 tag = 0);
        void eraseSymbol(address_t address);
        void setDocumentEntry(address_t address);
        SymbolPtr documentEntry() const;
        size_t segmentsCount() const;
        Segment *segment(address_t address);
        const Segment *segment(address_t address) const;
        const Segment *segmentAt(size_t idx) const;
        const Segment *segmentByName(const std::string& name) const;
        void instruction(const InstructionPtr& instruction);
        void update(const InstructionPtr& instruction);
        InstructionPtr instruction(address_t address);
        ListingDocument::iterator functionItem(address_t address);
        ListingDocument::iterator instructionItem(address_t address);
        ListingDocument::iterator symbolItem(address_t address);
        ListingDocument::iterator item(address_t address);
        int functionIndex(address_t address);
        int instructionIndex(address_t address);
        int symbolIndex(address_t address);
        ListingItem* itemAt(size_t i);
        int indexOf(address_t address);
        int indexOf(ListingItem *item);
        SymbolPtr symbol(address_t address);
        SymbolPtr symbol(const std::string& name);
        SymbolTable* symbols();
        InstructionCache* instructions();
        FormatPlugin* format();

    private:
        void pushSorted(address_t address, u32 type);
        void removeSorted(address_t address, u32 type);
        ListingDocument::iterator item(address_t address, u32 type);
        int index(address_t address, u32 type);
        static std::string normalized(std::string s);
        static std::string symbolName(const std::string& prefix, address_t address, const Segment* segment = NULL);

    private:
        std::mutex m_mutex;
        ListingCursor m_cursor;
        SegmentList m_segments;
        FunctionList m_functions;
        InstructionCache m_instructions;
        SymbolTable m_symboltable;
        FormatPlugin* m_format;
        SymbolPtr m_documententry;
        CommentMap m_comments;

     friend class FormatPlugin;
};

} // namespace REDasm

#endif // ITEMDOCUMENT_H
