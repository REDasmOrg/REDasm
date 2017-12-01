#ifndef REFERENCETABLE_H
#define REFERENCETABLE_H

#include <unordered_map>
#include <vector>
#include <set>
#include "symboltable.h"

namespace REDasm {

typedef std::vector<InstructionPtr> ReferenceVector;
typedef std::set<InstructionPtr> ReferenceSet;
typedef std::unordered_map<address_t, ReferenceSet> ReferenceMap;

class ReferenceTable
{
    public:
        ReferenceTable();
        void push(const SymbolPtr &symbol, const InstructionPtr& instruction);
        bool hasReferences(const SymbolPtr &symbol) const;
        ReferenceMap::const_iterator begin() const;
        ReferenceMap::const_iterator end() const;
        ReferenceMap::const_iterator references(const SymbolPtr& symbol) const;
        u64 referencesCount(const SymbolPtr &symbol) const;
        ReferenceVector referencesToVector(const SymbolPtr &symbol) const;

    public:
        static ReferenceVector toVector(const ReferenceSet& refset);

    private:
        ReferenceMap _references;
};

}

#endif // REFERENCETABLE_H
