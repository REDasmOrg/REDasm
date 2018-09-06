#include "symboltable.h"
#include "../../support/serializer.h"

namespace REDasm {

// SymbolCache
void SymbolCache::serialize(const SymbolPtr &value, std::fstream &fs)
{
    Serializer::serializeScalar(fs, value->type);
    Serializer::serializeScalar(fs, value->tag);
    Serializer::serializeScalar(fs, value->address);
    Serializer::serializeScalar(fs, value->size);
    Serializer::serializeString(fs, value->name);
    Serializer::serializeString(fs, value->cpu);
}

void SymbolCache::deserialize(SymbolPtr &value, std::fstream &fs)
{
    value = std::make_shared<Symbol>();
    Serializer::deserializeScalar(fs, &value->type);
    Serializer::deserializeScalar(fs, &value->tag);
    Serializer::deserializeScalar(fs, &value->address);
    Serializer::deserializeScalar(fs, &value->size);
    Serializer::deserializeString(fs, value->name);
    Serializer::deserializeString(fs, value->cpu);
}

// SymbolTable
SymbolTable::SymbolTable(): m_epaddress(0), m_isepvalid(false) {  }
u64 SymbolTable::size() const { return m_addresses.size(); }

bool SymbolTable::create(address_t address, const std::string &name, u32 type, u32 tag)
{
    auto it = m_byaddress.find(address);

    if(it != m_byaddress.end())
    {
        SymbolPtr symbol = *it;

        if(symbol->isLocked())
            return false;
    }

    if(type & SymbolTypes::EntryPointMask)
    {
        m_isepvalid = true;
        m_epaddress = address;
    }

    m_addresses.push_back(address);
    m_byaddress.commit(address, std::make_shared<Symbol>(type, tag, address, name));
    m_byname[name] = address;
    return it == m_byaddress.end();
}

SymbolPtr SymbolTable::entryPoint()
{
    if(!m_isepvalid)
        return NULL;

    return symbol(this->m_epaddress);
}

SymbolPtr SymbolTable::symbol(const std::string &name)
{
    auto it = m_byname.find(name);

    if(it != m_byname.end())
        return m_byaddress[it->second];

    return NULL;
}

SymbolPtr SymbolTable::symbol(address_t address)
{
    auto it = m_byaddress.find(address);

    if(it == m_byaddress.end())
        return NULL;

    return *it;
}

SymbolPtr SymbolTable::at(u64 index)
{
    if(index >= m_addresses.size())
        throw std::runtime_error("SymbolTable[]: Index out of range");

    return this->symbol(m_addresses[index]);
}

void SymbolTable::setEntryPoint(const SymbolPtr &symbol)
{
    m_isepvalid = true;
    m_epaddress = symbol->address;
}

void SymbolTable::iterate(u32 symbolflags, std::function<bool (const SymbolPtr&)> f)
{
    std::list<SymbolPtr> symbols;

    for(auto it = m_byaddress.begin(); it != m_byaddress.end(); it++)
    {
        SymbolPtr symbol = *it;

        if(!((symbol->type & SymbolTypes::LockedMask) & symbolflags))
            continue;

        symbols.push_back(symbol);
    }

    for(auto it = symbols.begin(); it != symbols.end(); it++)
    {
        if(!f(*it))
            break;
    }
}

bool SymbolTable::erase(address_t address)
{
    auto it = m_byaddress.find(address);

    if(it == m_byaddress.end())
        return false;

    SymbolPtr symbol = *it;

    if(!symbol || symbol->is(SymbolTypes::Locked))
        return false;

    m_byaddress.erase(it);
    m_byname.erase(symbol->name);
    return true;
}

void SymbolTable::sort()
{
    std::sort(m_addresses.begin(), m_addresses.end(), std::less<address_t>());
}

}
