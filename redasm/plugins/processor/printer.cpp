#include "printer.h"

namespace REDasm {

Printer::Printer(SymbolTable *symboltable): _symboltable(symboltable)
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

        if(it->is(OperandTypes::Immediate) || it->is(OperandTypes::Memory))
        {
            Symbol* symbol = this->_symboltable->symbol(it->is(OperandTypes::Immediate) ? operand.s_value : operand.u_value);

            if(symbol)
                opstr = symbol->name;
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

CapstonePrinter::CapstonePrinter(csh cshandle, SymbolTable *symboltable): Printer(symboltable), _cshandle(cshandle)
{

}

std::string CapstonePrinter::reg(const RegisterOperand& regop) const
{
    return cs_reg_name(this->_cshandle, regop.r);
}

} // namespace REDasm
