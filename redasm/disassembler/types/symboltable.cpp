#include "symboltable.h"

namespace REDasm {

// SymbolCache
void SymbolCache::serialize(const SymbolPtr &value, std::fstream &fs)
{
    Serializer::serializeScalar(fs, value->type);
    Serializer::serializeScalar(fs, value->address);
    Serializer::serializeString(fs, value->name);
}

void SymbolCache::deserialize(SymbolPtr &value, std::fstream &fs)
{
    value = std::make_shared<Symbol>();
    Serializer::deserializeScalar(fs, &value->type);
    Serializer::deserializeScalar(fs, &value->address);
    Serializer::deserializeString(fs, value->name);
}

// SymbolTable
SymbolTable::SymbolTable()
{

}

u64 SymbolTable::size() const
{
    return this->_addresses.size();
}

bool SymbolTable::contains(address_t address)
{
    return this->_byaddress.find(address) != this->_byaddress.end();
}

bool SymbolTable::create(address_t address, const std::string &name, u32 type)
{
    auto it = this->_byaddress.find(address);

    if(it != this->_byaddress.end())
    {
        this->promoteSymbol(*it, name, type);
        return false;
    }

    this->_addresses.push_back(address);
    this->_byaddress.commit(address, std::make_shared<Symbol>(type, address, name));
    this->_byname[name] = address;
    return true;
}

SymbolPtr SymbolTable::entryPoint()
{
    return this->symbol(ENTRYPOINT_FUNCTION);
}

SymbolPtr SymbolTable::symbol(const std::string &name)
{
    auto it = this->_byname.find(name);

    if(it != this->_byname.end())
        return this->_byaddress[it->second];

    return NULL;
}

SymbolPtr SymbolTable::symbol(address_t address)
{
    auto it = this->_byaddress.find(address);

    if(it == this->_byaddress.end())
        return NULL;

    return *it;
}

SymbolPtr SymbolTable::at(u64 index)
{
    if(index >= this->_addresses.size())
        throw std::runtime_error("SymbolTable[]: Index out of range");

    return this->symbol(this->_addresses[index]);
}

void SymbolTable::iterate(u32 symbolflags, std::function<bool (const SymbolPtr&)> f)
{
    std::list<SymbolPtr> symbols;

    for(auto it = this->_byaddress.begin(); it != this->_byaddress.end(); it++)
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
    auto it = this->_byaddress.find(address);

    if(it == this->_byaddress.end())
        return false;

    SymbolPtr symbol = *it;

    if(!symbol || symbol->is(SymbolTypes::Locked))
        return false;

    this->eraseInVector(address);
    this->_byaddress.erase(it);
    this->_byname.erase(symbol->name);
    return true;
}

bool SymbolTable::update(SymbolPtr symbol, const std::string& name)
{
    if(!symbol || (symbol->name == name))
        return false;

    auto it = this->_byname.find(symbol->name);

    if(it == this->_byname.end())
        return false;

    symbol->name = name;
    this->_byname[name] = symbol->address;
    this->_byname.erase(it);
    this->_byaddress.commit(symbol->address, symbol);
    return true;
}

void SymbolTable::sort()
{
    std::sort(this->_addresses.begin(), this->_addresses.end(), std::less<address_t>());
}

bool SymbolTable::createFunction(address_t address)
{
    return this->createFunction(address, REDasm::symbol("sub", address));
}

bool SymbolTable::createFunction(address_t address, const std::string &name)
{
    return this->create(address, name, SymbolTypes::Function);
}

bool SymbolTable::createString(address_t address)
{
    return this->create(address, REDasm::symbol("str", address), SymbolTypes::String);
}

bool SymbolTable::createWString(address_t address)
{
    return this->create(address, REDasm::symbol("wstr", address), SymbolTypes::WideString);
}

bool SymbolTable::createLocation(address_t address, u32 type)
{
    return this->create(address, REDasm::symbol("loc", address), type);
}

void SymbolTable::promoteSymbol(SymbolPtr symbol, const std::string &name, u32 type)
{
    if(symbol->is(SymbolTypes::Locked) || symbol->is(SymbolTypes::Function))
        return;

    if(symbol->is(SymbolTypes::Data) && (type & SymbolTypes::Code))
    {
        symbol->name = name;
        symbol->type = type;
    }

    this->_byaddress.commit(symbol->address, symbol);
}

void SymbolTable::eraseInVector(address_t address)
{
    for(auto it = this->_addresses.begin(); it < this->_addresses.end(); it++)
    {
        if(*it != address)
            continue;

        this->_addresses.erase(it);
        break;
    }
}

}
