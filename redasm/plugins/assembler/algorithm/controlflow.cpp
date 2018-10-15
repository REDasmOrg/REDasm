#include "controlflow.h"

namespace REDasm {

ControlFlowAlgorithm::ControlFlowAlgorithm(DisassemblerAPI *disassembler, AssemblerPlugin *assemblerplugin): AssemblerAlgorithm(disassembler, assemblerplugin) { }

void ControlFlowAlgorithm::addressTableState(const State *state)
{
    AssemblerAlgorithm::addressTableState(state);

    for(address_t target : state->instruction->targets)
        this->enqueue(target);
}

void ControlFlowAlgorithm::onDecoded(const InstructionPtr &instruction)
{
    AssemblerAlgorithm::onDecoded(instruction);

    for(address_t target : instruction->targets)
        this->enqueue(target);

    if(!instruction->is(InstructionTypes::Stop))
    {
        if(instruction->is(InstructionTypes::Jump) && !instruction->is(InstructionTypes::Conditional))
            return;

        this->enqueue(instruction->endAddress());
    }
}

} // namespace REDasm
