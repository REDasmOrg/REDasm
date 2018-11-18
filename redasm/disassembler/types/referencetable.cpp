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
size_t ReferenceTable::size() const { return m_references.size(); }

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

void ReferenceTable::serializeTo(std::fstream &fs)
{
    Serializer::serializeScalar(fs, m_references.size(), sizeof(u64));

    for(auto it = m_references.begin(); it != m_references.end(); it++)
    {
        Serializer::serializeScalar(fs, it->first);

        Serializer::serializeArray<std::set, address_t>(fs, it->second, [&](address_t ref) {
            Serializer::serializeScalar(fs, ref);
        });
    }
}

void ReferenceTable::deserializeFrom(std::fstream &fs)
{
    u64 count = 0;
    Serializer::deserializeScalar(fs, &count);

    for(u64 i = 0; i < count; i++)
    {
        address_t address = 0;
        ReferenceSet references;

        Serializer::deserializeScalar(fs, &address);

        Serializer::deserializeArray<std::set, address_t>(fs, references, [&](address_t& ref) {
            Serializer::deserializeScalar(fs, &ref);
        });

        m_references[address] = references;
    }
}

ReferenceVector ReferenceTable::toVector(const ReferenceSet &refset)
{
    ReferenceVector rv;
    std::for_each(refset.begin(), refset.end(), [&rv](address_t address) { rv.push_back(address); });
    return rv;
}

}
