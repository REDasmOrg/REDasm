#ifndef MIPSPRINTER_H
#define MIPSPRINTER_H

#include "../../plugins/processor/printer.h"

namespace REDasm {

class MIPSPrinter : public CapstonePrinter
{
    public:
        MIPSPrinter(csh cshandle, SymbolTable* symboltable);

    protected:
        virtual std::string reg(const RegisterOperand& regop) const;
        virtual std::string mem(const MemoryOperand& memop) const;
};

}

#endif // MIPSPRINTER_H
