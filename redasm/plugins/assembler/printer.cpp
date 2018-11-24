#include "printer.h"
#include "../../plugins/format.h"

#define HEADER_SYMBOL_COUNT 20

namespace REDasm {

Printer::Printer(DisassemblerAPI *disassembler): m_disassembler(disassembler) { m_document = m_disassembler->document(); }

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

void Printer::segment(const Segment *segment, Printer::LineCallback segmentfunc)
{
    std::string s(HEADER_SYMBOL_COUNT, '=');
    int bits = m_disassembler->format()->bits();

    segmentfunc(s + " SEGMENT " + (segment ? REDasm::quoted(segment->name) : "???") +
                " START: " + REDasm::hex(segment->address, bits) +
                " END: " + REDasm::hex(segment->endaddress, bits) + " " + s);
}

void Printer::function(const SymbolPtr &symbol, Printer::FunctionCallback functionfunc)
{
    std::string s(HEADER_SYMBOL_COUNT, '=');
    functionfunc(s + " FUNCTION ", symbol->name, " " + s);
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

    Segment* segment = m_disassembler->document()->segment(symbol->address);

    if(!segment)
        return;

    if(symbol->is(SymbolTypes::Pointer))
    {
        SymbolPtr ptrsymbol = m_disassembler->dereferenceSymbol(symbol);

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

        FormatPlugin* formatplugin = m_disassembler->format();
        u64 value = 0;

        if(!m_disassembler->readAddress(symbol->address, formatplugin->addressWidth(), &value))
            return;

        symbolfunc(symbol, REDasm::hex(value, formatplugin->addressWidth()));
    }
    else if(symbol->is(SymbolTypes::WideStringMask))
        symbolfunc(symbol, " \"" + m_disassembler->readWString(symbol->address) + "\"");
    else if(symbol->is(SymbolTypes::String))
        symbolfunc(symbol, " \"" + m_disassembler->readString(symbol->address) + "\"");
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
        BufferRef buffer = m_disassembler->format()->buffer(instruction->address);
        std::string hexstring = REDasm::hexstring(buffer, instruction->size);

        s += hexstring;
        opfunc(Operand(), std::string(), hexstring);
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
            if(operand.is(OperandTypes::Immediate))
               opstr = this->imm(operand);
            else if(operand.is(OperandTypes::Memory))
               opstr = this->mem(operand);
            else if(operand.is(OperandTypes::Displacement))
               opstr = this->disp(operand.disp);
            else if(operand.is(OperandTypes::Register))
               opstr = this->reg(operand.reg);
            else
                continue;
        }

        std::string opsize = this->size(operand);

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

    if(dispop.displacement)
    {
        if(dispop.displacement > 0)
        {
            SymbolPtr symbol = m_document->symbol(dispop.displacement);

            if(symbol)
                s += symbol->name;
            else
                s += REDasm::hex(dispop.displacement);
        }
        else
            s += REDasm::hex(dispop.displacement);
    }

    if(dispop.base.isValid())
    {
        if(dispop.displacement >= 0)
        {
            if(dispop.displacement > 0)
                s += " + ";

            s += this->reg(dispop.base);
        }
        else
            s = this->reg(dispop.base) + " - " + s;
    }

    if(dispop.index.isValid())
    {
        s += "[" + this->reg(dispop.index);

        if(dispop.scale > 1)
            s += " * " + REDasm::hex(dispop.scale);

        s += "]";
    }
    else
        return "[" + s + "]";

    return s;
}

std::string Printer::loc(const Operand &operand) const
{
    RE_UNUSED(operand);
    return std::string();
}

std::string Printer::mem(const Operand &operand) const { return this->imm(operand); }

std::string Printer::imm(const Operand &operand) const
{
    SymbolPtr symbol = m_disassembler->document()->symbol(operand.u_value);

    if(operand.is(OperandTypes::Memory))
        return "[" + (symbol ? symbol->name : REDasm::hex(operand.u_value)) + "]";

    return symbol ? symbol->name : REDasm::hex(operand.s_value);
}

std::string Printer::size(const Operand &operand) const { return OperandSizes::size(operand.size); }

CapstonePrinter::CapstonePrinter(csh cshandle, DisassemblerAPI *disassembler): Printer(disassembler), m_cshandle(cshandle) { }

std::string CapstonePrinter::reg(const RegisterOperand& regop) const
{
    if(regop.r <= 0)
    {
        REDasm::log("Unknown register with id " + std::to_string(regop.r));
        return "unkreg";
    }

    return cs_reg_name(m_cshandle, static_cast<unsigned int>(regop.r));
}

} // namespace REDasm
