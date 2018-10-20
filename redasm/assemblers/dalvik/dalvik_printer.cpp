#include "dalvik_printer.h"
#include "dalvik_metadata.h"
#include "../../formats/dex/dex.h"
#include "../../formats/dex/dex_constants.h"

namespace REDasm {

DalvikPrinter::DalvikPrinter(DisassemblerAPI *disassembler): Printer(disassembler)
{

}

void DalvikPrinter::function(const SymbolPtr &symbol, Printer::FunctionCallback headerfunc)
{
    DEXFormat* dexformat = dynamic_cast<DEXFormat*>(m_disassembler->format());

    if(!dexformat)
    {
        Printer::function(symbol, headerfunc);
        return;
    }

    // Reset printer data
    m_regnames.clear();
    m_regoverrides.clear();
    m_currentdbginfo.line_start = DEX_NO_INDEX_U;

    DEXEncodedMethod dexmethod;
    std::string access;

    if(dexformat->getMethodInfo(symbol->tag, dexmethod))
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

    headerfunc(access + dexformat->getReturnType(symbol->tag) + " ",
               symbol->name, dexformat->getParameters(symbol->tag));
}

void DalvikPrinter::prologue(const SymbolPtr &symbol, Printer::LineCallback prologuefunc)
{
    DEXFormat* dexformat = dynamic_cast<DEXFormat*>(m_disassembler->format());

    if(!dexformat)
        return;

    DEXEncodedMethod dexmethod;

    if(!dexformat->getMethodInfo(symbol->tag, dexmethod))
        return;

    if(!dexformat->getDebugInfo(symbol->tag, m_currentdbginfo))
        return;

    u32 delta = (dexmethod.access_flags & DexAccessFlags::Static) ? 0 : 1;

    for(auto it = m_currentdbginfo.parameter_names.begin(); it != m_currentdbginfo.parameter_names.end(); it++)
    {
        u64 argidx = std::distance(m_currentdbginfo.parameter_names.begin(), it) + delta;
        prologuefunc(".arg" + std::to_string(argidx) + ": " + *it);
    }
}

void DalvikPrinter::info(const InstructionPtr &instruction, Printer::LineCallback infofunc)
{
    if(m_currentdbginfo.line_start == DEX_NO_INDEX_U)
        return;

    auto dbgit = m_currentdbginfo.debug_data.find(instruction->address);

    if(dbgit == m_currentdbginfo.debug_data.end())
        return;

    DEXFormat* dexformat = dynamic_cast<DEXFormat*>(m_disassembler->format());

    if(!dexformat)
        return;

    for(auto it = dbgit->second.begin(); it != dbgit->second.end(); it++)
    {
        const DEXDebugData& debugdata = *it;

        if((debugdata.data_type == DEXDebugDataTypes::StartLocal) || ((debugdata.data_type == DEXDebugDataTypes::StartLocalExtended)))
        {
            if(debugdata.name_idx == DEX_NO_INDEX)
                continue;

            this->startLocal(dexformat, debugdata);
            std::string name = dexformat->getString(debugdata.name_idx), type;

            if(debugdata.type_idx != DEX_NO_INDEX)
                type = ": " + dexformat->getType(debugdata.type_idx);

            infofunc(".local " + this->registerName(debugdata.register_num) + " = " + name + type);
        }
        else if(debugdata.data_type == DEXDebugDataTypes::RestartLocal)
            this->restoreLocal(dexformat, debugdata.register_num);
        else if(debugdata.data_type == DEXDebugDataTypes::EndLocal)
            this->endLocal(debugdata.register_num);
        else if(debugdata.data_type == DEXDebugDataTypes::PrologueEnd)
            infofunc(".prologue_end");
        else if(debugdata.data_type == DEXDebugDataTypes::Line)
            infofunc(".line " + std::to_string(debugdata.line_no));
    }
}

std::string DalvikPrinter::reg(const RegisterOperand &regop) const
{
    std::string s;

    auto it = m_regnames.find(regop.r);

    if(it != m_regnames.end())
        s = it->second;
    else
        s = DalvikPrinter::registerName(regop.r);

    if(regop.extra_type & DalvikOperands::ParameterFirst)
        s = "{" + s;

    if(regop.extra_type & DalvikOperands::ParameterLast)
        s += "}";

    return s;
}

std::string DalvikPrinter::imm(const Operand &op) const
{
    DEXFormat* dexformat = NULL;

    if(op.extra_type && (dexformat = dynamic_cast<DEXFormat*>(m_disassembler->format())))
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

std::string DalvikPrinter::registerName(register_t r) { return "v" + std::to_string(r); }

void DalvikPrinter::startLocal(DEXFormat* dexformat, const DEXDebugData &debugdata)
{
    m_regoverrides[debugdata.register_num] = debugdata;
    m_regnames[debugdata.register_num] = dexformat->getString(debugdata.name_idx);
}

void DalvikPrinter::restoreLocal(DEXFormat* dexformat, register_t r)
{
    auto it = m_regoverrides.find(r);

    if(it == m_regoverrides.end())
        return;

    const DEXDebugData& debugdata = it->second;
    m_regnames[r] = dexformat->getString(debugdata.name_idx);
}

void DalvikPrinter::endLocal(register_t r)
{
    auto it = m_regnames.find(r);

    if(it != m_regnames.end())
        m_regnames.erase(it);
}

} // namespace REDasm
