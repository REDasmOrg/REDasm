#include "chip8printer.h"
#include <sstream>

namespace REDasm {

CHIP8Printer::CHIP8Printer(DisassemblerFunctions *disassembler, SymbolTable *symboltable): Printer(disassembler, symboltable)
{

}

std::string CHIP8Printer::reg(const RegisterOperand &regop) const
{
    std::stringstream ss;

    if(regop.type == 1) // key
        ss << "v";
    else
        ss << "r";

    ss << std::hex << regop.r;
    return ss.str();
}

} // namespace REDasm
