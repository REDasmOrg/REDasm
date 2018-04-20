#include "printer.h"
#include "../../plugins/format.h"

namespace REDasm {

Printer::Printer(DisassemblerAPI *disassembler, SymbolTable *symboltable): _disassembler(disassembler), _symboltable(symboltable)
{

}

void Printer::symbols(const InstructionPtr &instruction, Printer::SymbolCallback symbolfunc)
{
    std::for_each(instruction->references.begin(), instruction->references.end(), [this, symbolfunc](address_t ref) {
        SymbolPtr symbol = this->_disassembler->symbolTable()->symbol(ref);

        if(symbol)
            this->symbol(symbol, symbolfunc);
    });
}

std::string Printer::symbol(const SymbolPtr &symbol) const
{
    if(symbol->is(SymbolTypes::Pointer))
        return symbol->name;

    std::string s;

    this->symbol(symbol, [&s](const SymbolPtr&, std::string line) {
        s = line;
    });

    return s;
}

std::string Printer::out(const InstructionPtr &instruction) const
{
    return this->out(instruction, [](const Operand&, const std::string&, const std::string&) { });
}

void Printer::header(const SymbolPtr &symbol, Printer::HeaderCallback headerfunc)
{
    std::string s(20, '=');
    headerfunc(s + " FUNCTION ", symbol->name, " " + s);
}

void Printer::prologue(const SymbolPtr &symbol, Printer::LineCallback prologuefunc)
{
    RE_UNUSED(symbol);
    RE_UNUSED(prologuefunc);
}

void Printer::symbol(const SymbolPtr &symbol, SymbolCallback symbolfunc) const
{
    if(symbol->isFunction() || symbol->is(SymbolTypes::Code))
        return;

    FormatPlugin* formatplugin = this->_disassembler->format();
    Segment* segment = formatplugin->segment(symbol->address);

    if(!segment)
        return;

    if(symbol->is(SymbolTypes::Pointer))
    {
        SymbolPtr ptrsymbol = this->_disassembler->dereferenceSymbol(symbol);

        if(ptrsymbol)
        {
            symbolfunc(symbol, ptrsymbol->name);
            this->symbol(ptrsymbol, symbolfunc); // Emit pointed symbol too
            return;
        }
    }

    if(symbol->is(SymbolTypes::Data))
    {
        if(segment->is(SegmentTypes::Bss))
        {
            symbolfunc(symbol, "??");
            return;
        }

        u64 value = 0;

        if(!this->_disassembler->readAddress(symbol->address, formatplugin->addressWidth(), &value))
            return;

        symbolfunc(symbol, REDasm::hex(value, formatplugin->addressWidth()));
    }
    else if(symbol->is(SymbolTypes::WideStringMask))
        symbolfunc(symbol, " \"" + this->_disassembler->readWString(symbol->address) + "\"");
    else if(symbol->is(SymbolTypes::String))
        symbolfunc(symbol, " \"" + this->_disassembler->readString(symbol->address) + "\"");
}

void Printer::info(const InstructionPtr &instruction, LineCallback infofunc)
{
    RE_UNUSED(instruction);
    RE_UNUSED(infofunc);
}

std::string Printer::out(const InstructionPtr &instruction, Printer::OpCallback opfunc) const
{
    const OperandList& operands = instruction->operands;
    std::string s = instruction->mnemonic;

    if(instruction->isInvalid())
    {
        s += instruction->bytes;
        opfunc(Operand(), std::string(), instruction->bytes);
        return s;
    }

    if(!operands.empty())
        s += " ";

    for(auto it = operands.begin(); it != operands.end(); it++)
    {
        if(it != operands.begin())
            s += ", ";

        std::string opstr;
        const Operand& operand = *it;

        if(operand.is(OperandTypes::Local) || operand.is(OperandTypes::Argument))
            opstr = this->loc(operand);

        if(opstr.empty()) // Try with default algorithm...
        {
           if(operand.isNumeric())
               opstr = this->imm(operand);
            else if(operand.is(OperandTypes::Displacement))
               opstr = this->disp(operand.disp);
            else if(operand.is(OperandTypes::Register))
               opstr = this->reg(operand.reg);
            else
                continue;
        }

        std::string opsize = OperandSizes::size(operand.size);

        if(opfunc)
            opfunc(operand, opsize, opstr);

        if(!opsize.empty())
            s += opsize + " ";

        s += opstr;
    }

    return s;
}

std::string Printer::reg(const RegisterOperand &regop) const
{
    return "$" + std::to_string(regop.r);
}

std::string Printer::disp(const DisplacementOperand &dispop) const
{
    std::string s;

    if(dispop.base.isValid())
        s += this->reg(dispop.base);

    if(dispop.index.isValid())
    {
        if(!s.empty())
            s += " + ";

        s += this->reg(dispop.index);

        if(dispop.scale > 1)
            s += " * " + REDasm::hex(dispop.scale);
    }

    if(dispop.displacement)
    {
        SymbolPtr symbol = this->_symboltable->symbol(dispop.displacement);

        if(!s.empty() && ((dispop.displacement > 0) || symbol))
            s += " + ";

        s += symbol ? symbol->name : REDasm::hex(dispop.displacement);
    }

    if(!s.empty())
        return "[" + s + "]";

    return std::string();
}

std::string Printer::loc(const Operand &operand) const
{
    RE_UNUSED(operand);
    return std::string();
}

std::string Printer::imm(const Operand &operand) const
{
    SymbolPtr symbol = this->_symboltable->symbol(operand.u_value);

    if(operand.is(OperandTypes::Memory))
        return "[" + (symbol ? symbol->name : REDasm::hex(operand.u_value)) + "]";

    return symbol ? symbol->name : REDasm::hex(operand.s_value);
}

CapstonePrinter::CapstonePrinter(csh cshandle, DisassemblerAPI *disassembler, SymbolTable *symboltable): Printer(disassembler, symboltable), _cshandle(cshandle)
{

}

std::string CapstonePrinter::reg(const RegisterOperand& regop) const
{
    if(regop.r <= 0)
    {
        REDasm::log("Unknown register with id " + std::to_string(regop.r));
        return "unkreg";
    }

    return cs_reg_name(this->_cshandle, regop.r);
}

} // namespace REDasm
