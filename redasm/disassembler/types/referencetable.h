#ifndef REFERENCETABLE_H
#define REFERENCETABLE_H

#include <unordered_map>
#include <vector>
#include <set>
#include "symboltable.h"

namespace REDasm {

typedef std::vector<address_t> ReferenceVector;

class ReferenceTable
{
    private:
        typedef std::set<address_t> ReferenceSet;
        typedef std::unordered_map<address_t, ReferenceSet> ReferenceMap;

    public:
        ReferenceTable();
        void push(const SymbolPtr &symbol, address_t address);
        bool hasReferences(const SymbolPtr &symbol) const;
        ReferenceMap::const_iterator begin() const;
        ReferenceMap::const_iterator end() const;
        ReferenceMap::const_iterator references(const SymbolPtr& symbol) const;
        u64 referencesCount(const SymbolPtr &symbol) const;
        ReferenceVector referencesToVector(const SymbolPtr &symbol) const;
        ReferenceVector referencesToVector(address_t address) const;

    public:
        static ReferenceVector toVector(const ReferenceSet& refset);

    private:
        ReferenceMap _references;
};

}

#endif // REFERENCETABLE_H
