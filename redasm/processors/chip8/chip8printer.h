#ifndef CHIP8PRINTER_H
#define CHIP8PRINTER_H

#define CHIP8_REG_K   1
#define CHIP8_REG_I   2
#define CHIP8_REG_DT  3
#define CHIP8_REG_ST  4

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
