#include "metaarm_algorithm.h"
#include "metaarm.h"
#include <capstone.h>

namespace REDasm {

MetaARMAlgorithm::MetaARMAlgorithm(DisassemblerAPI *disassembler, AssemblerPlugin *assembler): ControlFlowAlgorithm(disassembler, assembler)
{
    REGISTER_STATE(MetaARMAlgorithm::SwitchAssemblerState, &MetaARMAlgorithm::switchAssemblerState);
}

void MetaARMAlgorithm::onEmulatedOperand(const Operand &op, const InstructionPtr &instruction, u64 value)
{
    MetaARMAssembler* metaarmassembler = static_cast<MetaARMAssembler*>(m_assembler);

    if(metaarmassembler->isPC(op)) // Don't generate references for PC register
        return;

    ControlFlowAlgorithm::onEmulatedOperand(op, instruction, value);
}

void MetaARMAlgorithm::enqueueTarget(address_t target, const InstructionPtr &instruction)
{
    address_t ctarget = target & 0xFFFFFFFE;
    ControlFlowAlgorithm::enqueueTarget(ctarget, instruction);

    if((instruction->id == ARM_INS_BX) || (instruction->id == ARM_INS_BLX))
    {
        if(target & 1)
            m_document->comment(instruction->address, "@ " + REDasm::hex(ctarget, m_format->bits(), false) + " -> THUMB");
        else
            m_document->comment(instruction->address, "@ " + REDasm::hex(ctarget, m_format->bits(), false) + " -> ARM");

        ENQUEUE_VALUE(MetaARMAlgorithm::SwitchAssemblerState, target);
    }
}

void MetaARMAlgorithm::switchAssemblerState(State *state)
{
    MetaARMAssembler* metaarmassembler = static_cast<MetaARMAssembler*>(m_assembler);

    if(state->address & 1)
        metaarmassembler->switchToThumb();
    else
        metaarmassembler->switchToARM();
}

} // namespace REDasm
