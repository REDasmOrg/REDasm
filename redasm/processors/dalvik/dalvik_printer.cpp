#include "dalvik_printer.h"
#include "dalvik_metadata.h"
#include "../../formats/dex/dex.h"

namespace REDasm {

DalvikPrinter::DalvikPrinter(DisassemblerFunctions *disassembler, SymbolTable *symboltable): Printer(disassembler, symboltable)
{

}

void DalvikPrinter::prologue(const SymbolPtr &symbol, Printer::PrologueCallback plgfunc)
{
    DEXFormat* dexformat = dynamic_cast<DEXFormat*>(this->_disassembler->format());

    if(!dexformat)
    {
        Printer::prologue(symbol, plgfunc);
        return;
    }

    plgfunc(dexformat->getReturnType(symbol->extra_type) + " ", symbol->name, dexformat->getParameters(symbol->extra_type));
}

std::string DalvikPrinter::reg(const RegisterOperand &regop) const
{
    return "v" + std::to_string(regop.r);
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
                return dexformat->getMethod(op.u_value);

            default:
                break;
        }
    }

    return Printer::imm(op);
}

} // namespace REDasm
