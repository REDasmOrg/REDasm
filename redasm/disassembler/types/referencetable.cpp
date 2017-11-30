#include "referencetable.h"
#include <algorithm>

namespace REDasm {

ReferenceTable::ReferenceTable()
{

}

void ReferenceTable::push(Symbol *symbol, const InstructionPtr &instruction)
{
    auto it = this->_references.find(symbol->address);

    if(it == this->_references.end())
    {
        ReferenceSet rs;
        rs.insert(instruction);
        this->_references[symbol->address] = rs;
        return;
    }

    it->second.insert(instruction);
}

bool ReferenceTable::hasReferences(Symbol *symbol) const
{
    return this->references(symbol) != this->_references.end();
}

ReferenceMap::const_iterator ReferenceTable::begin() const
{
    return this->_references.begin();
}

ReferenceMap::const_iterator ReferenceTable::end() const
{
    return this->_references.end();
}

ReferenceMap::const_iterator ReferenceTable::references(const REDasm::Symbol* symbol) const
{
    return this->_references.find(symbol->address);
}

u64 ReferenceTable::referencesCount(const Symbol *symbol) const
{
    auto it = this->references(symbol);

    if(it != this->_references.end())
        return it->second.size();

    return 0;
}

ReferenceVector ReferenceTable::referencesToVector(const Symbol *symbol) const
{
    auto it = this->_references.find(symbol->address);

    if(it == this->_references.end())
        return ReferenceVector();

    return ReferenceTable::toVector(it->second);
}

ReferenceVector ReferenceTable::toVector(const ReferenceSet &refset)
{
    ReferenceVector rv;
    std::for_each(refset.begin(), refset.end(), [&rv](const InstructionPtr& instruction) { rv.push_back(instruction); });
    return rv;
}

}
