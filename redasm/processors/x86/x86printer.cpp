#include "x86printer.h"

namespace REDasm {

X86Printer::X86Printer(csh cshandle, SymbolTable* symboltable): CapstonePrinter(cshandle, symboltable)
{

}

std::string X86Printer::mem(const MemoryOperand &memop) const
{
    std::string s;

    if(memop.base.isValid())
        s += this->reg(memop.base);

    if(memop.index.isValid())
    {
        if(!s.empty())
            s += " + ";

        s += this->reg(memop.index);

        if(memop.scale > 1)
            s += " * " + REDasm::hex(memop.scale);
    }

    if(memop.displacement)
    {
        Symbol* symbol = this->_symboltable->symbol(memop.displacement);

        if(!s.empty() && ((memop.displacement > 0) || symbol))
            s += " + ";

        s += symbol ? symbol->name : REDasm::hex(memop.displacement);
    }

    if(!s.empty())
        return "[" + s + "]";

    return std::string();
}

}
