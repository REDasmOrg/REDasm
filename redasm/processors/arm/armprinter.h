#ifndef ARMPRINTER_H
#define ARMPRINTER_H

#include "../../plugins/processor/printer.h"

namespace REDasm {

class ARMPrinter: public CapstonePrinter
{
    public:
        ARMPrinter(csh cshandle, DisassemblerFunctions* disassembler, SymbolTable* symboltable);
};

} // namespace REDasm

#endif // ARMPRINTER_H
