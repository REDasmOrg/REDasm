#ifndef X86PRINTER_H
#define X86PRINTER_H

#include "../../plugins/processor/printer.h"

namespace REDasm {

class X86Printer : public CapstonePrinter
{
    public:
        X86Printer(csh cshandle, SymbolTable *symboltable);

    protected:
        virtual std::string mem(const MemoryOperand& memop) const;
};

}

#endif // X86PRINTER_H
