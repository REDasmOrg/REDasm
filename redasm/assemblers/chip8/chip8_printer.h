#ifndef CHIP8_PRINTER_H
#define CHIP8_PRINTER_H

#include "../../plugins/assembler/printer.h"

namespace REDasm {

class CHIP8Printer : public Printer
{
    public:
        CHIP8Printer(DisassemblerAPI* disassembler);
        virtual std::string reg(const RegisterOperand& regop) const;
};

} // namespace REDasm

#endif // CHIP8_PRINTER_H
