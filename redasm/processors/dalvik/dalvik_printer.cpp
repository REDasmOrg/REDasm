#include "dalvik_printer.h"
#include "dalvik_metadata.h"
#include "../../formats/dex/dex.h"

namespace REDasm {

DalvikPrinter::DalvikPrinter(DisassemblerFunctions *disassembler, SymbolTable *symboltable): Printer(disassembler, symboltable)
{

}

void DalvikPrinter::header(const SymbolPtr &symbol, Printer::HeaderCallback plgfunc)
{
    DEXFormat* dexformat = dynamic_cast<DEXFormat*>(this->_disassembler->format());

    if(!dexformat)
    {
        Printer::header(symbol, plgfunc);
        return;
    }

    plgfunc(dexformat->getReturnType(symbol->extra_type) + " ", symbol->name, dexformat->getParameters(symbol->extra_type));
}

std::string DalvikPrinter::reg(const RegisterOperand &regop) const
{
    std::string s = "v" + std::to_string(regop.r);

    if(regop.extra_type & DalvikOperands::ParameterFirst)
        s = "{" + s;

    if(regop.extra_type & DalvikOperands::ParameterLast)
        s += "}";

    return s;
}

std::string DalvikPrinter::imm(const Operand &op) const
{
    DEXFormat* dexformat = NULL;

    if(op.extra_type && (dexformat = dynamic_cast<DEXFormat*>(this->_disassembler->format())))
    {
        switch(op.extra_type)
        {
            case DalvikOperands::StringIndex:
                return REDasm::quoted(dexformat->getString(op.u_value));

            case DalvikOperands::TypeIndex:
                return dexformat->getType(op.u_value);

            case DalvikOperands::MethodIndex:
                return dexformat->getMethodProto(op.u_value);

            case DalvikOperands::FieldIndex:
                return dexformat->getField(op.u_value);

            default:
                break;
        }
    }

    return Printer::imm(op);
}

} // namespace REDasm
