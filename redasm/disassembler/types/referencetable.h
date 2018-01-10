#ifndef REFERENCETABLE_H
#define REFERENCETABLE_H

#include "../../redasm.h"

namespace REDasm {

typedef std::vector<address_t> ReferenceVector;

class ReferenceTable
{
    private:
        typedef std::set<address_t> ReferenceSet;
        typedef std::unordered_map<address_t, ReferenceSet> ReferenceMap;

    public:
        ReferenceTable();
        void push(address_t address, address_t refbyaddress);
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
