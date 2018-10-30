#include "referencetable.h"
#include <algorithm>

namespace REDasm {

ReferenceTable::ReferenceTable() { }

void ReferenceTable::push(address_t address, address_t refbyaddress)
{
    auto it = m_references.find(address);

    if(it == m_references.end())
    {
        ReferenceSet rs;
        rs.insert(refbyaddress);
        m_references[address] = rs;
        return;
    }

    it->second.insert(refbyaddress);
}

bool ReferenceTable::hasReferences(address_t address) const { return this->references(address) != m_references.end(); }
ReferenceTable::ReferenceMap::const_iterator ReferenceTable::begin() const { return m_references.begin(); }
ReferenceTable::ReferenceMap::const_iterator ReferenceTable::end() const { return m_references.end(); }
ReferenceTable::ReferenceMap::const_iterator ReferenceTable::references(address_t address) const { return m_references.find(address); }

u64 ReferenceTable::referencesCount(address_t address) const
{
    auto it = this->references(address);

    if(it != m_references.end())
        return it->second.size();

    return 0;
}

ReferenceVector ReferenceTable::referencesToVector(address_t address) const
{
    auto it = m_references.find(address);

    if(it == m_references.end())
        return ReferenceVector();

    return ReferenceTable::toVector(it->second);
}

ReferenceVector ReferenceTable::toVector(const ReferenceSet &refset)
{
    ReferenceVector rv;
    std::for_each(refset.begin(), refset.end(), [&rv](address_t address) { rv.push_back(address); });
    return rv;
}

}
