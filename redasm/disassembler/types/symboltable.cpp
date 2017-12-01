#include "symboltable.h"

namespace REDasm {

// SymbolCache
void SymbolCache::serialize(const SymbolPtr &value, std::fstream &fs)
{
    fs.write(reinterpret_cast<const char*>(&value->type), sizeof(u32));
    fs.write(reinterpret_cast<const char*>(&value->address), sizeof(address_t));
    Serializer::serialize(fs, value->name);
}

void SymbolCache::deserialize(SymbolPtr &value, std::fstream &fs)
{
    fs.read(reinterpret_cast<char*>(&value->type), sizeof(u32));
    fs.read(reinterpret_cast<char*>(&value->address), sizeof(address_t));
    Serializer::deserialize(fs, value->name);
}

// SymbolTable
SymbolTable::SymbolTable()
{

}

u64 SymbolTable::size() const
{
    return this->_addresses.size();
}

bool SymbolTable::contains(address_t address) const
{
    return this->_byaddress.contains(address);
}

bool SymbolTable::create(address_t address, const std::string &name, u32 type)
{
    if(this->_byaddress.contains(address))
    {
        this->promoteSymbol(address, name, type);
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
    {
        SymbolPtr symbol = std::make_shared<Symbol>();

        if(this->_byaddress.get(it->second, symbol))
            return symbol;
    }

    return NULL;
}

SymbolPtr SymbolTable::symbol(address_t address)
{
    if(!this->_byaddress.contains(address))
        return NULL;

    SymbolPtr symbol = std::make_shared<Symbol>();
    this->_byaddress.get(address, symbol);
    return symbol;
}

SymbolPtr SymbolTable::at(u64 index)
{
    if(index >= this->_addresses.size())
        throw std::runtime_error("SymbolTable[]: Index out of range");

    SymbolPtr symbol = std::make_shared<Symbol>();
    this->_byaddress.get(this->_addresses[index], symbol);
    return symbol;
}

std::string SymbolTable::getName(address_t address)
{
    if(!this->_byaddress.contains(address))
        return std::string();

    SymbolPtr symbol = std::make_shared<Symbol>();

    if(this->_byaddress.get(address, symbol))
        return symbol->name;

    return std::string();
}

void SymbolTable::iterate(u32 symbolflags, std::function<bool (const SymbolPtr&)> f)
{
    std::list<SymbolPtr> symbols;

    for(auto it = this->_byaddress.begin(); it != this->_byaddress.end(); it++)
    {
        SymbolPtr symbol = this->symbol(it->first);

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
    if(!this->_byaddress.contains(address))
        return false;

    SymbolPtr symbol = this->symbol(address);

    if(!symbol || symbol->is(SymbolTypes::Locked))
        return false;

    this->eraseInVector(address);
    this->_byaddress.erase(address);
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

void SymbolTable::promoteSymbol(address_t address, const std::string &name, u32 type)
{
    SymbolPtr symbol = std::make_shared<Symbol>();

    if(!this->_byaddress.get(address, symbol) || symbol->is(SymbolTypes::Locked) || symbol->is(SymbolTypes::Function))
        return;

    if(symbol->is(SymbolTypes::Data) && (type & SymbolTypes::Code))
    {
        symbol->name = name;
        symbol->type = type;
    }

    this->_byaddress.commit(address, symbol);
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
