#ifndef SYMBOLTABLE_H
#define SYMBOLTABLE_H

#include <functional>
#include <unordered_map>
#include <map>
#include "../../support/cachemap.h"
#include "../../redasm.h"

#define IS_LABEL(symbol)      (symbol && !symbol->isFunction() && symbol->is(REDasm::SymbolTypes::Code))

namespace REDasm {

namespace SymbolTypes {
    enum: u32 {
        None               = 0x00000000,
        Data               = 0x00000001, String = 0x00000002, Code = 0x00000004,

        Function           = 0x00000100 | Code,
        EntryPoint         = 0x00001000 | Function,
        Import             = 0x00002000 | Data,
        ExportData         = 0x00004000 | Data,
        ExportFunction     = 0x00008000 | Function,
        WideString         = 0x01000000 | String,
        Pointer            = 0x02000000,
        Locked             = 0x10000000,

        LockedMask         = ~Locked,
        FunctionMask       = Function                      & ~(Code      | Locked),
        ExportMask         = (ExportData | ExportFunction) & ~(Function  | Data | Locked),
        ImportMask         = Import                        & ~(Data      | Locked),
        EntryPointMask     = EntryPoint                    & ~(Function),
        StringMask         = String                        & ~(Pointer),
        WideStringMask     = WideString                    & ~(String    | Pointer),
    };
}

struct Symbol
{
    Symbol(): type(0), extra_type(0), address(0) { }
    Symbol(u32 type, u32 extratype, address_t address, const std::string& name): type(type), extra_type(extratype), address(address), name(name) { }
    void lock() { type |= SymbolTypes::Locked; }

    u32 type, extra_type;
    address_t address;
    std::string name;

    bool is(u32 t) const { return type & t; }
    bool isFunction() const { return type & SymbolTypes::FunctionMask; }
};

typedef std::shared_ptr<Symbol> SymbolPtr;

class SymbolCache: public cache_map<address_t, SymbolPtr>
{
    public:
        SymbolCache(): cache_map<address_t, SymbolPtr>("symboltable") { }
        virtual ~SymbolCache() { }

    protected:
        virtual void serialize(const SymbolPtr& value, std::fstream& fs);
        virtual void deserialize(SymbolPtr& value, std::fstream& fs);
};

class SymbolTable
{
    private:
        typedef std::unordered_map<std::string, address_t> SymbolsByName;

    public:
        SymbolTable();
        u64 size() const;
        bool contains(address_t address);
        bool create(address_t address, const std::string& name, u32 type, u32 extratype = 0);
        SymbolPtr entryPoint();
        SymbolPtr symbol(address_t address);
        SymbolPtr symbol(const std::string& name);
        SymbolPtr at(u64 index);
        void setEntryPoint(const SymbolPtr& symbol);
        void iterate(u32 symbolflags, std::function<bool(const SymbolPtr &)> f);
        bool erase(address_t address);
        bool update(SymbolPtr symbol, const std::string &name);
        void sort();

    public:
        bool createFunction(address_t address);
        bool createFunction(address_t address, const std::string& name);
        bool createString(address_t address);
        bool createWString(address_t address);
        bool createLocation(address_t address, u32 type);

    private:
        void promoteSymbol(SymbolPtr symbol, const std::string& name, u32 type);
        void eraseInVector(address_t address);

    private:
        AddressList _addresses;
        SymbolsByName _byname;
        SymbolCache _byaddress;
        address_t _epaddress;
        bool _isepvalid;
};

}

#endif // SYMBOLTABLE_H
