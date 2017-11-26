#include "symboltable.h"

namespace REDasm {

SymbolTable::SymbolTable()
{

}

u64 SymbolTable::size() const
{
    return this->_addresses.size();
}

bool SymbolTable::contains(address_t address) const
{
    return this->_byaddress.find(address) != this->_byaddress.end();
}

bool SymbolTable::create(address_t address, const std::string &name, u32 flags)
{
    auto it = this->_byaddress.find(address);

    if(it != this->_byaddress.end())
        return false;

    this->_addresses.push_back(address);
    this->_byaddress[address] = Symbol(flags, address, name);
    this->_byname[name] = address;
    return true;
}

Symbol *SymbolTable::entryPoint()
{
    return this->symbol(ENTRYPOINT_FUNCTION);
}

Symbol *SymbolTable::symbol(const std::string &name)
{
    auto it = this->_byname.find(name);

    if(it != this->_byname.end())
        return &(this->_byaddress[it->second]);

    return NULL;
}

Symbol *SymbolTable::symbol(address_t address)
{
    auto it = this->_byaddress.find(address);

    if(it != this->_byaddress.end())
        return &it->second;

    return NULL;
}

Symbol *SymbolTable::at(u64 index)
{
    return const_cast<Symbol*>(static_cast<const Symbol*>(this->at(index)));
}

const Symbol *SymbolTable::at(u64 index) const
{
    if(index >= this->_addresses.size())
        throw std::runtime_error("SymbolTable[]: Index out of range");

    return &(this->_byaddress.at(this->_addresses[index]));
}

const Symbol* SymbolTable::getNearestLocation(address_t address) const
{
    SymbolsByAddress::const_iterator nit = this->_byaddress.lower_bound(address), it = nit;

    while(it != this->_byaddress.end())
    {
        const Symbol& symbol = it->second;

        if((symbol.address == address) || symbol.isFunction())
            return &symbol;

        if(it == this->_byaddress.begin())
            break;

        it--;
    }

    if(nit != this->_byaddress.end())
        return &(nit->second);

    return NULL;
}

std::string SymbolTable::getName(address_t address) const
{
    auto it = this->_byaddress.find(address);

    if(it != this->_byaddress.end())
        return it->second.name;

    return std::string();
}

void SymbolTable::iterate(u32 symbolflags, std::function<bool (Symbol *)> f)
{
    std::list<Symbol*> symbols;

    for(auto it = this->_byaddress.begin(); it != this->_byaddress.end(); it++)
    {
        Symbol* symbol = &(it->second);

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

    Symbol* symbol = this->symbol(address);

    if(!symbol || symbol->is(SymbolTypes::Locked))
        return false;

    this->eraseInVector(address);
    this->_byaddress.erase(it);
    this->_byname.erase(symbol->name);
    return true;
}

bool SymbolTable::rename(Symbol *symbol, const std::string& name)
{
    if(!symbol || (symbol->name == name))
        return false;

    auto it = this->_byname.find(symbol->name);

    if(it == this->_byname.end())
        return false;

    symbol->name = name;
    this->_byname[name] = symbol->address;
    this->_byname.erase(it);
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
