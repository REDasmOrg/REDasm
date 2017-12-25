#include "chip8printer.h"
#include "chip8registers.h"
#include <sstream>

namespace REDasm {

CHIP8Printer::CHIP8Printer(DisassemblerFunctions *disassembler, SymbolTable *symboltable): Printer(disassembler, symboltable)
{

}

std::string CHIP8Printer::reg(const RegisterOperand &regop) const
{
    if(regop.type == CHIP8_REG_I)
        return "i";

    if(regop.type == CHIP8_REG_DT)
        return "dt";

    if(regop.type == CHIP8_REG_ST)
        return "st";

    std::stringstream ss;
    ss << ((regop.type == CHIP8_REG_K) ? "k" : "v") << std::hex << regop.r;
    return ss.str();
}

} // namespace REDasm
