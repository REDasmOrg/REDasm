#ifndef X86PRINTER_H
#define X86PRINTER_H

#include "../../plugins/processor/printer.h"

namespace REDasm {

class X86Printer: public CapstonePrinter
{
    public:
        X86Printer(csh cshandle, DisassemblerFunctions *disassembler, SymbolTable *symboltable);
        virtual std::string loc(const Operand &op) const;
};

} // namespace REDasm

#endif // X86PRINTER_H
