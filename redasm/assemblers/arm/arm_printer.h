#ifndef ARM_PRINTER_H
#define ARM_PRINTER_H

#include "../../plugins/assembler/printer.h"

namespace REDasm {

class ARMPrinter: public CapstonePrinter
{
    public:
        ARMPrinter(csh cshandle, DisassemblerAPI* disassembler, SymbolTable* symboltable);
        virtual std::string ptr(const std::string &expr) const;
};

} // namespace REDasm

#endif // ARM_PRINTER_H
