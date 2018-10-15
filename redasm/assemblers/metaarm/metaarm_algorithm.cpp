#include "metaarm_algorithm.h"
#include "metaarm.h"
#include <capstone.h>

namespace REDasm {

MetaARMAlgorithm::MetaARMAlgorithm(DisassemblerAPI *disassembler, AssemblerPlugin *assembler): ControlFlowAlgorithm(disassembler, assembler)
{
    REGISTER_STATE(MetaARMAlgorithm::SwitchAssemblerState, &MetaARMAlgorithm::switchAssemblerState);
}

void MetaARMAlgorithm::onEmulatedOperand(const InstructionPtr &instruction, const Operand &op)
{
    if(instruction->id == ARM_INS_BX)
    {
        u64 value = 0;

        if(!m_emulator->read(op, &value))
            return;

        ENQUEUE_STATE(MetaARMAlgorithm::SwitchAssemblerState, value, op.index, instruction);
        return;
    }

    ControlFlowAlgorithm::onEmulatedOperand(instruction, op);
}

void MetaARMAlgorithm::switchAssemblerState(const State *state)
{
    MetaARMAssembler* metaarmassembler = static_cast<MetaARMAssembler*>(m_assembler);
    address_t target = state->u_value & 0xFFFFFFFE;

    if(state->u_value & 1)
    {
        m_document->comment(state->instruction->address, "@ " + REDasm::hex(target, m_format->bits(), false) + " -> THUMB");
        metaarmassembler->switchToThumb();
    }
    else
    {
        m_document->comment(state->instruction->address, "@ " + REDasm::hex(target, m_format->bits(), false) + " -> ARM");
        metaarmassembler->switchToARM();
    }

    this->enqueue(target);
    FORWARD_STATE_VALUE(MetaARMAlgorithm::BranchState, target, state);
}

} // namespace REDasm
