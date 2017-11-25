#ifndef DISASSEMBLER_H
#define DISASSEMBLER_H

#define MIN_STRING       4
#define MAX_STRING       100

#include <functional>
#include "../plugins/plugins.h"
#include "symboltable.h"
#include "referencetable.h"
#include "listing.h"

namespace REDasm {

class Disassembler
{
    public:
        typedef std::function<void(std::string)> ReportCallback;

    public:
        Disassembler(Buffer buffer, ProcessorPlugin* processor, FormatPlugin* format);
        ~Disassembler();
        void loggerCallback(const ReportCallback& cb);
        void statusCallback(const ReportCallback& cb);
        u64 locationIsString(address_t address, bool *wide = NULL) const;
        std::string readString(address_t address) const;
        std::string readWString(address_t address) const;
        Listing &listing();
        Buffer& buffer();

    public:
        std::string out(const InstructionPtr& instruction, std::function<void(const Operand&, const std::string&)> opfunc);
        std::string out(const InstructionPtr& instruction);
        std::string comment(const InstructionPtr& instruction) const;
        bool dataToString(address_t address);
        void disassembleFunction(address_t address);
        void disassemble();

    private:
        template<typename T> std::string readStringT(address_t address, std::function<bool(T, std::string&)> fill) const;
        template<typename T> u64 locationIsStringT(address_t address, std::function<bool(T)> isp, std::function<bool(T)> isa) const;
        bool readAddress(address_t address, size_t size, u64 &value);
        bool readOffset(offset_t offset, size_t size, u64 &value);
        void checkJumpTable(const InstructionPtr& instruction, const Operand &op);
        bool analyzeTarget(const InstructionPtr& instruction);
        void analyzeOp(const InstructionPtr& instruction, const Operand& operand);
        void disassemble(address_t address);
        InstructionPtr disassembleInstruction(address_t address, Buffer &b);

    public:
        FormatPlugin* format();
        ProcessorPlugin* processor();
        SymbolTable* symbols();
        ReferenceTable* references();

    private:
        ReportCallback _logcallback;
        ReportCallback _statuscallback;
        SymbolTable _symboltable;
        ReferenceTable _referencetable;
        ProcessorPlugin* _processor;
        FormatPlugin* _format;
        PrinterPtr _printer;
        Listing _listing;
        Buffer _buffer;
};

template<typename T> std::string Disassembler::readStringT(address_t address, std::function<bool(T, std::string&)> fill) const
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

template<typename T> u64 Disassembler::locationIsStringT(address_t address, std::function<bool(T)> isp, std::function<bool(T)> isa) const
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

}

#endif // DISASSEMBLER_H
