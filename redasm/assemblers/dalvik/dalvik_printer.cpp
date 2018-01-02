#include "dalvik_printer.h"
#include "dalvik_metadata.h"
#include "../../formats/dex/dex.h"
#include "../../formats/dex/dex_constants.h"

namespace REDasm {

DalvikPrinter::DalvikPrinter(DisassemblerFunctions *disassembler, SymbolTable *symboltable): Printer(disassembler, symboltable)
{

}

void DalvikPrinter::header(const SymbolPtr &symbol, Printer::HeaderCallback headerfunc)
{
    DEXFormat* dexformat = dynamic_cast<DEXFormat*>(this->_disassembler->format());

    if(!dexformat)
    {
        Printer::header(symbol, headerfunc);
        return;
    }

    DEXEncodedMethod dexmethod;

    std::string access;

    if(dexformat->getMethodInfo(symbol->extra_type, dexmethod))
    {
        if(dexmethod.access_flags & DexAccessFlags::Public)
            access += access.empty() ? "public" : " public";

        if(dexmethod.access_flags & DexAccessFlags::Protected)
            access += access.empty() ? "protected" : " protected";

        if(dexmethod.access_flags & DexAccessFlags::Private)
            access += access.empty() ? "private" : " private";

        if(dexmethod.access_flags & DexAccessFlags::Static)
            access += access.empty() ? "static" : " static";

        if(!access.empty())
            access += " ";
    }

    headerfunc(access + dexformat->getReturnType(symbol->extra_type) + " ",
               symbol->name, dexformat->getParameters(symbol->extra_type));
}

void DalvikPrinter::prologue(const SymbolPtr &symbol, Printer::PrologueCallback prologuefunc)
{
    DEXFormat* dexformat = dynamic_cast<DEXFormat*>(this->_disassembler->format());

    if(!dexformat)
        return;

    DEXEncodedMethod dexmethod;

    if(!dexformat->getMethodInfo(symbol->extra_type, dexmethod))
        return;

    DEXDebugInfo dexdebuginfo;

    if(!dexformat->getDebugInfo(symbol->extra_type, dexdebuginfo))
        return;

    u32 delta = (dexmethod.access_flags & DexAccessFlags::Static) ? 0 : 1;

    for(auto it = dexdebuginfo.parameter_names.begin(); it != dexdebuginfo.parameter_names.end(); it++)
    {
        u32 argidx = std::distance(dexdebuginfo.parameter_names.begin(), it) + delta;
        prologuefunc(".arg" + std::to_string(argidx) + ": " + *it);
    }
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
