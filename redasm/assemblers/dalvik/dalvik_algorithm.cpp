#include "dalvik_algorithm.h"
#include "../../formats/dex/dex.h"

namespace REDasm {

DalvikAlgorithm::DalvikAlgorithm(DisassemblerAPI* disassembler, AssemblerPlugin* assemblerplugin): ControlFlowAlgorithm(disassembler, assemblerplugin)
{
    REGISTER_STATE(DalvikAlgorithm::StringIndexState, &DalvikAlgorithm::stringIndexState);
    REGISTER_STATE(DalvikAlgorithm::MethodIndexState, &DalvikAlgorithm::methodIndexState);
}

void DalvikAlgorithm::onDecodedOperand(const Operand& op, const InstructionPtr &instruction)
{
    if(op.extra_type == DalvikOperands::StringIndex)
        ENQUEUE_STATE(DalvikAlgorithm::StringIndexState, op.extra_type, op.index, instruction);
    else if(op.extra_type == DalvikOperands::MethodIndex)
        ENQUEUE_STATE(DalvikAlgorithm::MethodIndexState, op.extra_type, op.index, instruction);
}

void DalvikAlgorithm::stringIndexState(const State *state)
{
    DEXFormat* dexformat = dynamic_cast<DEXFormat*>(m_format);

    if(!dexformat)
        return;

    const Operand& op = state->operand();
    offset_t offset = 0;

    if(!dexformat->getStringOffset(op.u_value, offset))
        return;

    m_document->symbol(offset, SymbolTypes::String);
    m_disassembler->pushReference(offset, state->instruction->address);
}

void DalvikAlgorithm::methodIndexState(const State *state)
{
    DEXFormat* dexformat = dynamic_cast<DEXFormat*>(m_format);

    if(!dexformat)
        return;

    const Operand& op = state->operand();
    offset_t offset = 0;

    if(!dexformat->getMethodOffset(op.u_value, offset))
        return;

    m_disassembler->pushReference(offset, state->instruction->address);
}

} // namespace REDasm
