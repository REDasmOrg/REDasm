#include "armprinter.h"

namespace REDasm {

ARMPrinter::ARMPrinter(csh cshandle, DisassemblerFunctions *disassembler, SymbolTable *symboltable): CapstonePrinter(cshandle, disassembler, symboltable)
{

}

std::string ARMPrinter::ptr(const std::string &expr) const
{
    return "=" + expr;
}

} // namespace REDasm
