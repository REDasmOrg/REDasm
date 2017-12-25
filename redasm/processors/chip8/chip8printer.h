#ifndef CHIP8PRINTER_H
#define CHIP8PRINTER_H

#include "../../plugins/processor/printer.h"

namespace REDasm {

class CHIP8Printer : public Printer
{
    public:
        CHIP8Printer(DisassemblerFunctions* disassembler, SymbolTable* symboltable);
        virtual std::string reg(const RegisterOperand& regop) const;
};

} // namespace REDasm

#endif // CHIP8PRINTER_H
