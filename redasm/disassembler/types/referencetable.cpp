#include "referencetable.h"
#include <algorithm>

namespace REDasm {

ReferenceTable::ReferenceTable()
{

}

void ReferenceTable::push(const SymbolPtr& symbol, address_t address)
{
    auto it = this->_references.find(symbol->address);

    if(it == this->_references.end())
    {
        ReferenceSet rs;
        rs.insert(address);
        this->_references[symbol->address] = rs;
        return;
    }

    it->second.insert(address);
}

bool ReferenceTable::hasReferences(address_t address) const
{
    return this->references(address) != this->_references.end();
}

ReferenceTable::ReferenceMap::const_iterator ReferenceTable::begin() const
{
    return this->_references.begin();
}

ReferenceTable::ReferenceMap::const_iterator ReferenceTable::end() const
{
    return this->_references.end();
}

ReferenceTable::ReferenceMap::const_iterator ReferenceTable::references(address_t address) const
{
    return this->_references.find(address);
}

u64 ReferenceTable::referencesCount(address_t address) const
{
    auto it = this->references(address);

    if(it != this->_references.end())
        return it->second.size();

    return 0;
}

ReferenceVector ReferenceTable::referencesToVector(address_t address) const
{
    auto it = this->_references.find(address);

    if(it == this->_references.end())
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
