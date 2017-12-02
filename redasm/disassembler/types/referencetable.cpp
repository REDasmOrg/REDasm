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

bool ReferenceTable::hasReferences(const SymbolPtr& symbol) const
{
    return this->references(symbol) != this->_references.end();
}

ReferenceTable::ReferenceMap::const_iterator ReferenceTable::begin() const
{
    return this->_references.begin();
}

ReferenceTable::ReferenceMap::const_iterator ReferenceTable::end() const
{
    return this->_references.end();
}

ReferenceTable::ReferenceMap::const_iterator ReferenceTable::references(const REDasm::SymbolPtr& symbol) const
{
    return this->_references.find(symbol->address);
}

u64 ReferenceTable::referencesCount(const SymbolPtr& symbol) const
{
    auto it = this->references(symbol);

    if(it != this->_references.end())
        return it->second.size();

    return 0;
}

ReferenceVector ReferenceTable::referencesToVector(const SymbolPtr& symbol) const
{
    auto it = this->_references.find(symbol->address);

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
