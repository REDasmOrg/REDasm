#ifndef PRINTER_H
#define PRINTER_H

#include <memory>
#include <capstone.h>
#include "../../redasm.h"
#include "../../disassembler/symboltable.h"

namespace REDasm {

class Printer
{
    public:
        Printer(SymbolTable* symboltable);
        virtual std::string out(const InstructionPtr& instruction, std::function<void(const Operand&, const std::string&)> opfunc) const;
        virtual std::string out(const InstructionPtr& instruction) const;

    protected:
        virtual std::string reg(const RegisterOperand& regop) const = 0;
        virtual std::string mem(const MemoryOperand& memop) const = 0;

    protected:
        SymbolTable* _symboltable;
};

class CapstonePrinter: public Printer
{
    public:
        CapstonePrinter(csh cshandle, SymbolTable* symboltable);

    protected:
        virtual std::string reg(const RegisterOperand &regop) const;

    private:
        csh _cshandle;
};

typedef std::shared_ptr<Printer> PrinterPtr;

}

#endif // PRINTER_H
