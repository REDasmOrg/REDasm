#include "dalvik_printer.h"
#include "dalvik_metadata.h"
#include "../../formats/dex/dex.h"

namespace REDasm {

DalvikPrinter::DalvikPrinter(DisassemblerFunctions *disassembler, SymbolTable *symboltable): Printer(disassembler, symboltable)
{

}

std::string DalvikPrinter::reg(const RegisterOperand &regop) const
{
    return "v" + std::to_string(regop.r);
}

std::string DalvikPrinter::imm(const Operand &op) const
{
    if(op.extra_type)
    {
        DEXFormat* dexformat = dynamic_cast<DEXFormat*>(this->_disassembler->format());

        if(dexformat && (op.extra_type == DalvikOperands::StringIndex))
            return REDasm::quoted(dexformat->getString(op.u_value));
        else if(dexformat && (op.extra_type == DalvikOperands::MethodIndex))
            return dexformat->getMethod(op.u_value);
    }

    return Printer::imm(op);
}

} // namespace REDasm
