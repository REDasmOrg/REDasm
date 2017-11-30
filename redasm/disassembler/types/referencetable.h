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
        void push(Symbol* symbol, const InstructionPtr& instruction);
        bool hasReferences(Symbol* symbol) const;
        ReferenceMap::const_iterator begin() const;
        ReferenceMap::const_iterator end() const;
        ReferenceMap::const_iterator references(const Symbol *symbol) const;
        u64 referencesCount(const Symbol *symbol) const;
        ReferenceVector referencesToVector(const Symbol *symbol) const;

    public:
        static ReferenceVector toVector(const ReferenceSet& refset);

    private:
        ReferenceMap _references;
};

}

#endif // REFERENCETABLE_H
