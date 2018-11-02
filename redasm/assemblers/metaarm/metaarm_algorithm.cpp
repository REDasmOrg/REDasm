#include "metaarm_algorithm.h"
#include "metaarm.h"
#include <capstone.h>

namespace REDasm {

MetaARMAlgorithm::MetaARMAlgorithm(DisassemblerAPI *disassembler, AssemblerPlugin *assembler): ControlFlowAlgorithm(disassembler, assembler) { }

void MetaARMAlgorithm::onEmulatedOperand(const Operand &op, const InstructionPtr &instruction, u64 value)
{
    MetaARMAssembler* metaarmassembler = static_cast<MetaARMAssembler*>(m_assembler);

    if(metaarmassembler->isPC(op) || metaarmassembler->isLR(op)) // Don't generate references for PC/LR registers
        return;

    ControlFlowAlgorithm::onEmulatedOperand(op, instruction, value);
}

void MetaARMAlgorithm::enqueueTarget(address_t target, const InstructionPtr &instruction)
{
    address_t ctarget = target & 0xFFFFFFFE;
    ControlFlowAlgorithm::enqueueTarget(ctarget, instruction);

    if(!m_document->segment(ctarget)) // Check for valid address
        return;

    if((instruction->id == ARM_INS_BX) || (instruction->id == ARM_INS_BLX))
    {
        if(target & 1)
            m_document->comment(instruction->address, "@ " + REDasm::hex(ctarget, m_format->bits()) + " -> THUMB");
        else
            m_document->comment(instruction->address, "@ " + REDasm::hex(ctarget, m_format->bits()) + " -> ARM");

        m_armstate[ctarget] = static_cast<bool>(target & 1);
        return;
    }

    // Propagate current state
    MetaARMAssembler* metaarm = static_cast<MetaARMAssembler*>(m_assembler);
    m_armstate[ctarget] = metaarm->isTHUMBMode();
}

void MetaARMAlgorithm::decodeState(State *state)
{
    auto it = m_armstate.find(state->address);

    if(it != m_armstate.end())
    {
        MetaARMAssembler* metaarm = static_cast<MetaARMAssembler*>(m_assembler);

        if(it->second)
            metaarm->switchToThumb();
        else
            metaarm->switchToARM();
    }

    ControlFlowAlgorithm::decodeState(state);
}

} // namespace REDasm
