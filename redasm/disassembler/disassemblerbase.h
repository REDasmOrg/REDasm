#ifndef DISASSEMBLERBASE_H
#define DISASSEMBLERBASE_H

#define MIN_STRING       4
#define MAX_STRING       200

#define STATUS(s) if(_statuscallback) _statuscallback((s));
#define LOG(s)    if(_logcallback) _logcallback((s));

#include <functional>
#include "../plugins/format.h"
#include "types/referencetable.h"
#include "disassemblerfunctions.h"

namespace REDasm {

class DisassemblerBase: public DisassemblerFunctions
{
    public:
        typedef std::function<void(std::string)> ReportCallback;

    public:
        DisassemblerBase(Buffer buffer, FormatPlugin* format);
        virtual ~DisassemblerBase();
        Buffer& buffer();
        FormatPlugin* format();
        SymbolTable* symbolTable();
        void loggerCallback(const ReportCallback& cb);
        void statusCallback(const ReportCallback& cb);
        bool hasReferences(const SymbolPtr &symbol);
        ReferenceVector getReferences(const SymbolPtr &symbol);
        u64 getReferencesCount(const SymbolPtr &symbol);

    public: // Primitive functions
        virtual u64 locationIsString(address_t address, bool *wide = NULL) const;
        virtual std::string readString(const SymbolPtr& symbol) const;
        virtual std::string readWString(const SymbolPtr& symbol) const;
        virtual SymbolPtr dereferenceSymbol(const SymbolPtr &symbol, u64 *value = NULL);
        virtual bool dereferencePointer(address_t address, u64& value) const;
        virtual bool readAddress(address_t address, size_t size, u64 &value) const;
        virtual bool readOffset(offset_t offset, size_t size, u64 &value) const;

   protected:
        std::string readString(address_t address) const;
        std::string readWString(address_t address) const;

   private:
        template<typename T> std::string readStringT(address_t address, std::function<bool(T, std::string&)> fill) const;
        template<typename T> u64 locationIsStringT(address_t address, std::function<bool(T)> isp, std::function<bool(T)> isa) const;

   protected:
        ReportCallback _logcallback;
        ReportCallback _statuscallback;
        ReferenceTable _referencetable;
        SymbolTable* _symboltable;
        FormatPlugin* _format;
        Buffer _buffer;
};

template<typename T> std::string DisassemblerBase::readStringT(address_t address, std::function<bool(T, std::string&)> fill) const
{
    Buffer b = this->_buffer + this->_format->offset(address);
    u64 count = 0;
    std::string s;

    while(fill(*reinterpret_cast<T*>(b.data), s) && !b.eob())
    {
        count++;

        if(count > MAX_STRING)
            break;

        b += sizeof(T);
    }

    if(count > MAX_STRING)
        s += "...";

    return "\"" + s + "\"";
}

template<typename T> u64 DisassemblerBase::locationIsStringT(address_t address, std::function<bool(T)> isp, std::function<bool(T)> isa) const
{
    if(!this->_format->segment(address))
        return 0;

    bool containsalpha = false;
    u64 count = 0;
    Buffer b = this->_buffer;
    b += this->_format->offset(address);

    while(isp(*reinterpret_cast<T*>(b.data)) && !b.eob())
    {
        count++;

        if(!containsalpha)
            containsalpha = isa(*reinterpret_cast<T*>(b.data));

        if(count >= MIN_STRING)
            break;

        b += sizeof(T);
    }

    if(!containsalpha) // ...it might be just data...
        return 0;

    return count;
}

} // namespace REDasm

#endif // DISASSEMBLERBASE_H
