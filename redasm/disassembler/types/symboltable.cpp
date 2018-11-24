#include "symboltable.h"
#include "../../support/serializer.h"

namespace REDasm {

SymbolTable::SymbolTable(): cache_map<address_t, SymbolPtr>("symboltable") { }

bool SymbolTable::create(address_t address, const std::string &name, u32 type, u32 tag)
{
    auto it = this->find(address);

    if(it != this->end())
    {
        SymbolPtr symbol = *it;

        if(symbol->isLocked())
            return false;
    }

    m_addresses.push_back(address);
    this->commit(address, std::make_shared<Symbol>(type, tag, address, name));
    m_byname[name] = address;
    return it == this->end();
}

SymbolPtr SymbolTable::symbol(const std::string &name)
{
    auto it = m_byname.find(name);

    if(it != m_byname.end())
        return this->value(it->second);

    return NULL;
}

SymbolPtr SymbolTable::symbol(address_t address)
{
    auto it = this->find(address);

    if(it == this->end())
        return NULL;

    return *it;
}

SymbolPtr SymbolTable::at(u64 index)
{
    if(index >= m_addresses.size())
        throw std::runtime_error("SymbolTable[]: Index out of range");

    return this->symbol(m_addresses[index]);
}

void SymbolTable::iterate(u32 symbolflags, std::function<bool (const SymbolPtr&)> f)
{
    std::list<SymbolPtr> symbols;

    for(auto it = this->begin(); it != this->end(); it++)
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
    auto it = this->find(address);

    if(it == this->end())
        return false;

    SymbolPtr symbol = *it;

    if(!symbol)
        return false;

    this->erase(it);
    m_byname.erase(symbol->name);
    return true;
}

void SymbolTable::deserializeFrom(std::fstream &fs)
{
    this->deserialized += std::bind(&SymbolTable::bindName, this, std::placeholders::_1);
    cache_map<address_t, SymbolPtr>::deserializeFrom(fs);
    this->deserialized.removeLast();
}

void SymbolTable::serialize(const SymbolPtr &value, std::fstream &fs)
{
    Serializer::serializeScalar(fs, value->type);
    Serializer::serializeScalar(fs, value->tag);
    Serializer::serializeScalar(fs, value->address);
    Serializer::serializeScalar(fs, value->size);
    Serializer::serializeString(fs, value->name);
    Serializer::serializeString(fs, value->cpu);
}

void SymbolTable::deserialize(SymbolPtr &value, std::fstream &fs)
{
    value = std::make_shared<Symbol>();
    Serializer::deserializeScalar(fs, &value->type);
    Serializer::deserializeScalar(fs, &value->tag);
    Serializer::deserializeScalar(fs, &value->address);
    Serializer::deserializeScalar(fs, &value->size);
    Serializer::deserializeString(fs, value->name);
    Serializer::deserializeString(fs, value->cpu);
}

void SymbolTable::bindName(const SymbolPtr &symbol) { m_byname[symbol->name] = symbol->address; }

}
