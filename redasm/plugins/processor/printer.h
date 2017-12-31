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
        typedef std::function<void(const Operand&, const std::string&, const std::string&)> OpCallback;
        typedef std::function<void(const std::string&, const std::string&, const std::string&)> PrologueCallback;

    public:
        Printer(DisassemblerFunctions* disassembler, SymbolTable* symboltable);
        virtual void prologue(const SymbolPtr& symbol, PrologueCallback plgfunc);
        virtual std::string out(const InstructionPtr& instruction, OpCallback opfunc) const;
        virtual std::string out(const InstructionPtr& instruction) const;

    public: // Operand privitives
        virtual std::string reg(const RegisterOperand& regop) const;
        virtual std::string mem(const MemoryOperand& memop) const;
        virtual std::string loc(const Operand& op) const;
        virtual std::string imm(const Operand& op) const;
        virtual std::string ptr(const std::string& expr) const;

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
