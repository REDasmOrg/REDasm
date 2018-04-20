#include "metaarm_printer.h"

namespace REDasm {

MetaARMPrinter::MetaARMPrinter(csh cshandle, DisassemblerAPI *disassembler, SymbolTable *symboltable): CapstonePrinter(cshandle, disassembler, symboltable)
{

}

} // namespace REDasm
