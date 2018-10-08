#include "controlflow.h"

namespace REDasm {

DisassemblerControlFlow::DisassemblerControlFlow(DisassemblerAPI *disassembler, AssemblerPlugin *assemblerplugin): DisassemblerAlgorithm(disassembler, assemblerplugin) { }

void DisassemblerControlFlow::addressTableState(const State *state)
{
    DisassemblerAlgorithm::addressTableState(state);

    for(address_t target : state->instruction->targets)
        this->enqueue(target);
}

void DisassemblerControlFlow::onDecoded(const InstructionPtr &instruction)
{
    DisassemblerAlgorithm::onDecoded(instruction);

    for(address_t target : instruction->targets)
        this->enqueue(target);

    if(!instruction->is(InstructionTypes::Stop))
        this->enqueue(instruction->endAddress());
}

} // namespace REDasm
