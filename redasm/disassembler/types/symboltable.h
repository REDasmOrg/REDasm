#ifndef SYMBOLTABLE_H
#define SYMBOLTABLE_H

#include <functional>
#include <unordered_map>
#include <map>
#include "../../redasm.h"

namespace REDasm {

namespace SymbolTypes {
    enum: u32 {
        None           = 0x00000000,
        Data           = 0x00000001, String = 0x00000002, Code = 0x00000004,

        Function       = 0x00000100 | Code,
        EntryPoint     = 0x00001000 | Function,
        Import         = 0x00002000 | Data,
        ExportData     = 0x00004000 | Data,
        ExportFunction = 0x00008000 | EntryPoint,
        WideString     = 0x01000000 | String,
        Pointer        = 0x02000000,
        Locked         = 0x10000000,

        LockedMask         = ~Locked,
        FunctionMask       = Function                      & ~(Code       | Locked),
        ExportMask         = (ExportData | ExportFunction) & ~(EntryPoint | Data | Locked),
        ImportMask         = Import                        & ~(Data       | Locked),
        StringMask         = String                        & ~(Pointer),
        WideStringMask     = WideString                    & ~(String     | Pointer),
    };
}

struct Symbol
{
    Symbol(): type(0), address(0) { }
    Symbol(u32 flags, address_t address, const std::string& name): type(flags), address(address), name(name) { }
    void lock() { type |= SymbolTypes::Locked; }

    u32 type;
    address_t address;
    std::string name;

    bool is(u32 t) const { return type & t; }
    bool isFunction() const { return type & SymbolTypes::FunctionMask; }
};

typedef std::map<address_t, Symbol> SymbolsByAddress;
typedef std::unordered_map<std::string, address_t> SymbolsByName;

class SymbolTable
{
    public:
        SymbolTable();
        u64 size() const;
        bool contains(address_t address) const;
        bool create(address_t address, const std::string& name, u32 type);
        Symbol* entryPoint();
        Symbol* symbol(address_t address);
        Symbol* symbol(const std::string& name);
        Symbol* at(u64 index);
        const Symbol *at(u64 index) const;
        const Symbol *getNearestLocation(address_t address) const;
        std::string getName(address_t address) const;
        void iterate(u32 symbolflags, std::function<bool(Symbol* symbol)> f);
        bool erase(address_t address);
        bool rename(Symbol* symbol, const std::string &name);
        void sort();

    public:
        bool createFunction(address_t address);
        bool createFunction(address_t address, const std::string& name);
        bool createString(address_t address);
        bool createWString(address_t address);
        bool createLocation(address_t address, u32 type);

    private:
        void promoteSymbol(Symbol* symbol, const std::string& name, u32 type);
        void eraseInVector(address_t address);

    private:
        AddressVector _addresses;
        SymbolsByAddress _byaddress;
        SymbolsByName _byname;
};

}

#endif // SYMBOLTABLE_H
