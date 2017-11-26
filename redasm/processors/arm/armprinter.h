#ifndef ARMPRINTER_H
#define ARMPRINTER_H

#include "../../plugins/processor/printer.h"

namespace REDasm {

class ARMPrinter: public CapstonePrinter
{
    public:
        ARMPrinter(csh cshandle, DisassemblerFunctions* disassembler, SymbolTable* symboltable);
        virtual std::string ptr(const std::string &expr) const;
};

} // namespace REDasm

#endif // ARMPRINTER_H
