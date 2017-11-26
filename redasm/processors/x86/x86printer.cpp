#include "x86printer.h"

namespace REDasm {

X86Printer::X86Printer(csh cshandle, DisassemblerFunctions *disassembler, SymbolTable *symboltable): CapstonePrinter(cshandle, disassembler, symboltable)
{

}

std::string X86Printer::loc(const Operand &op) const
{
    if(op.is(OperandTypes::Local))
        return "[local." + std::to_string(op.loc_index) + "]";
    else if(op.is(OperandTypes::Argument))
        return "[arg." + std::to_string(op.loc_index) + "]";

    return std::string();
}

} // namespace REDasm
