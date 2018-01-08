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
        bool hasReferences(address_t address) const;
        ReferenceMap::const_iterator begin() const;
        ReferenceMap::const_iterator end() const;
        ReferenceMap::const_iterator references(address_t address) const;
        u64 referencesCount(address_t address) const;
        ReferenceVector referencesToVector(address_t address) const;

    public:
        static ReferenceVector toVector(const ReferenceSet& refset);

    private:
        ReferenceMap _references;
};

}

#endif // REFERENCETABLE_H
