#ifndef MIPSPRINTER_H
#define MIPSPRINTER_H

#include "../../plugins/processor/printer.h"

namespace REDasm {

class MIPSPrinter : public CapstonePrinter
{
    public:
        MIPSPrinter(csh cshandle, DisassemblerFunctions* disassembler, SymbolTable* symboltable);
        virtual std::string reg(const RegisterOperand& regop) const;
        virtual std::string mem(const MemoryOperand& memop) const;
};

} // namespace REDasm

#endif // MIPS_PRINTER_H
