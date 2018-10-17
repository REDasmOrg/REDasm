#include "controlflow.h"

namespace REDasm {

ControlFlowAlgorithm::ControlFlowAlgorithm(DisassemblerAPI *disassembler, AssemblerPlugin *assemblerplugin): AssemblerAlgorithm(disassembler, assemblerplugin) { }

void ControlFlowAlgorithm::addressTableState(State *state)
{
    AssemblerAlgorithm::addressTableState(state);
    this->enqueueTargets(state->instruction);
}

void ControlFlowAlgorithm::enqueueTarget(address_t target, const InstructionPtr &frominstruction)
{
    RE_UNUSED(frominstruction);
    this->enqueue(target);
}

void ControlFlowAlgorithm::onEmulatedOperand(const Operand &op, const InstructionPtr &instruction, u64 value)
{
    if(instruction->is(InstructionTypes::Branch) && instruction->isTargetOperand(op))
    {
        this->enqueueTarget(value, instruction);
        ENQUEUE_STATE(AssemblerAlgorithm::BranchState, value, op.index, instruction);
        return;
    }

    AssemblerAlgorithm::onEmulatedOperand(op, instruction, value);
}

void ControlFlowAlgorithm::onDecoded(const InstructionPtr &instruction)
{
    AssemblerAlgorithm::onDecoded(instruction);
    this->enqueueTargets(instruction);

    if(!instruction->is(InstructionTypes::Stop))
    {
        if(instruction->is(InstructionTypes::Jump) && !instruction->is(InstructionTypes::Conditional))
            return;

        this->enqueue(instruction->endAddress());
    }
}

void ControlFlowAlgorithm::enqueueTargets(const InstructionPtr &instruction)
{
    for(address_t target : instruction->targets)
        this->enqueueTarget(target, instruction);
}

} // namespace REDasm
