#include "mips_printer.h"
#include "mips_quirks.h"

namespace REDasm {

MIPSPrinter::MIPSPrinter(csh cshandle, DisassemblerFunctions *disassembler, SymbolTable *symboltable): CapstonePrinter(cshandle, disassembler, symboltable)
{

}

std::string MIPSPrinter::reg(const RegisterOperand &regop) const
{
    if(regop.type & MIPSRegisterTypes::Cop2Register)
        return "$" + REDasm::dec(regop.r);

    return "$" + CapstonePrinter::reg(regop);
}

std::string MIPSPrinter::mem(const MemoryOperand &memop) const
{
    return REDasm::hex(memop.displacement) + "(" + this->reg(memop.base) + ")";
}

}
