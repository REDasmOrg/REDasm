#include "chip8_printer.h"
#include "chip8_registers.h"
#include <sstream>

namespace REDasm {

CHIP8Printer::CHIP8Printer(DisassemblerAPI *disassembler): Printer(disassembler)
{

}

std::string CHIP8Printer::reg(const RegisterOperand &regop) const
{
    if(regop.extra_type == CHIP8_REG_I)
        return "i";

    if(regop.extra_type == CHIP8_REG_DT)
        return "dt";

    if(regop.extra_type == CHIP8_REG_ST)
        return "st";

    std::stringstream ss;
    ss << ((regop.extra_type == CHIP8_REG_K) ? "k" : "v") << std::hex << regop.r;
    return ss.str();
}

} // namespace REDasm
