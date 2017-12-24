#ifndef PRINTER_H
#define PRINTER_H

#include <memory>
#include <capstone.h>
#include "../../redasm.h"
#include "../../disassembler/types/symboltable.h"
#include "../../disassembler/disassemblerfunctions.h"

namespace REDasm {

class Printer
{
    public:
        Printer(DisassemblerFunctions* disassembler, SymbolTable* symboltable);
        virtual std::string out(const InstructionPtr& instruction, std::function<void(const Operand&, const std::string&)> opfunc) const;
        virtual std::string out(const InstructionPtr& instruction) const;

    public: // Operand privitives
        virtual std::string reg(const RegisterOperand& regop) const = 0;
        virtual std::string mem(const MemoryOperand& memop) const;
        virtual std::string ptr(const std::string& expr) const;
        virtual std::string loc(const Operand& op) const;

    protected:
        DisassemblerFunctions* _disassembler;
        SymbolTable* _symboltable;
};

class CapstonePrinter: public Printer
{
    public:
        CapstonePrinter(csh cshandle, DisassemblerFunctions* disassembler, SymbolTable* symboltable);

    protected:
        virtual std::string reg(const RegisterOperand &regop) const;

    private:
        csh _cshandle;
};

typedef std::shared_ptr<Printer> PrinterPtr;

}

#endif // PRINTER_H
