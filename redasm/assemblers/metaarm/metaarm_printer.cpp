#include "metaarm_printer.h"

namespace REDasm {

MetaARMPrinter::MetaARMPrinter(csh cshandle, DisassemblerAPI *disassembler, SymbolTable *symboltable): CapstonePrinter(cshandle, disassembler, symboltable)
{

}

std::string MetaARMPrinter::ptr(const std::string &expr) const
{
    return "=" + expr;
}

} // namespace REDasm
