#include "dalvik_printer.h"

namespace REDasm {

DalvikPrinter::DalvikPrinter(DisassemblerFunctions *disassembler, SymbolTable *symboltable): Printer(disassembler, symboltable)
{

}

std::string DalvikPrinter::reg(const RegisterOperand &regop) const
{
    return "v" + std::to_string(regop.r);
}

} // namespace REDasm
