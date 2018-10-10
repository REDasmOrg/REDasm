#include "dex_algorithm.h"
#include "dex.h"

namespace REDasm {

DexAlgorithm::DexAlgorithm(DisassemblerAPI* disassembler, AssemblerPlugin* assemblerplugin): DisassemblerControlFlow(disassembler, assemblerplugin)
{
    REGISTER_STATE(DexAlgorithm::StringIndexState, &DexAlgorithm::stringIndexState);
    REGISTER_STATE(DexAlgorithm::MethodIndexState, &DexAlgorithm::methodIndexState);
}

void DexAlgorithm::onDecodedOperand(const InstructionPtr &instruction, const Operand& op)
{
    if(op.extra_type == DalvikOperands::StringIndex)
        ENQUEUE_STATE(DexAlgorithm::StringIndexState, op.extra_type, op.index, instruction);
    else if(op.extra_type == DalvikOperands::MethodIndex)
        ENQUEUE_STATE(DexAlgorithm::MethodIndexState, op.extra_type, op.index, instruction);
}

void DexAlgorithm::stringIndexState(const State *state)
{
    DEXFormat* dexformat = dynamic_cast<DEXFormat*>(m_format);

    if(!dexformat)
        return;

    const Operand& op = state->operand();
    offset_t offset = 0;

    if(!dexformat->getStringOffset(op.u_value, offset))
        return;

    m_document->symbol(offset, SymbolTypes::String);
    m_disassembler->pushReference(offset, state->instruction);
}

void DexAlgorithm::methodIndexState(const State *state)
{
    DEXFormat* dexformat = dynamic_cast<DEXFormat*>(m_format);

    if(!dexformat)
        return;

    const Operand& op = state->operand();
    offset_t offset = 0;

    if(!dexformat->getMethodOffset(op.u_value, offset))
        return;

    m_disassembler->pushReference(offset, state->instruction);
}

} // namespace REDasm
