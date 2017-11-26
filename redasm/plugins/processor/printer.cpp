#include "printer.h"

namespace REDasm {

Printer::Printer(DisassemblerFunctions *disassembler, SymbolTable *symboltable): _disassembler(disassembler), _symboltable(symboltable)
{

}

std::string Printer::out(const InstructionPtr &instruction, std::function<void (const Operand&, const std::string &)> opfunc) const
{
    const OperandList& operands = instruction->operands;
    std::string s = instruction->mnemonic;

    if(!operands.empty())
        s += " ";

    for(auto it = operands.begin(); it != operands.end(); it++)
    {
        if(it != operands.begin())
            s += ", ";

        std::string opstr;
        const Operand& operand = *it;

        if(it->is(OperandTypes::Local) || it->is(OperandTypes::Argument))
            opstr = this->loc(operand);

        if(opstr.empty()) // Try with default algorithm...
        {
           if(it->is(OperandTypes::Immediate) || it->is(OperandTypes::Memory))
            {
                Symbol* symbol = this->_symboltable->symbol(it->is(OperandTypes::Immediate) ? operand.s_value : operand.u_value);

                if(symbol)
                {
                    Symbol* ptrsymbol = NULL;

                    if(symbol->is(SymbolTypes::Pointer))
                    {
                        u64 ptrvalue;
                        ptrsymbol = this->_disassembler->dereferenceSymbol(symbol, &ptrvalue);
                        opstr = this->ptr(ptrsymbol ? ptrsymbol->name : REDasm::hex(ptrvalue));
                    }
                    else
                        opstr = symbol->name;
                }
                else if(it->is(OperandTypes::Immediate))
                    opstr = REDasm::hex(operand.s_value);
                else
                    opstr = REDasm::hex(operand.u_value);
            }
            else if(it->is(OperandTypes::Displacement))
                opstr = this->mem(operand.mem);
            else if(it->is(OperandTypes::Register))
                opstr = this->reg(operand.reg);
            else
                continue;
        }

        if(opfunc)
            opfunc(*it, opstr);

        s += opstr;
    }

    return s;
}

std::string Printer::out(const InstructionPtr &instruction) const
{
    return this->out(instruction, [](const Operand&, const std::string&) { });
}

std::string Printer::mem(const MemoryOperand &memop) const
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

std::string Printer::ptr(const std::string &expr) const
{
    return expr;
}

std::string Printer::loc(const Operand &op) const
{
    RE_UNUSED(op);

    return std::string();
}

CapstonePrinter::CapstonePrinter(csh cshandle, DisassemblerFunctions *disassembler, SymbolTable *symboltable): Printer(disassembler, symboltable), _cshandle(cshandle)
{

}

std::string CapstonePrinter::reg(const RegisterOperand& regop) const
{
    return cs_reg_name(this->_cshandle, regop.r);
}

} // namespace REDasm
