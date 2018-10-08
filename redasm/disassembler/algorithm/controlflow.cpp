#include "controlflow.h"

namespace REDasm {

DisassemblerControlFlow::DisassemblerControlFlow(DisassemblerAPI *disassembler, AssemblerPlugin *assemblerplugin): DisassemblerAlgorithm(disassembler, assemblerplugin) { }

void DisassemblerControlFlow::onDecoded(const InstructionPtr &instruction)
{
    DisassemblerAlgorithm::onDecoded(instruction);

    for(address_t target : instruction->targets)
        this->enqueue(target);

    if(!instruction->is(InstructionTypes::Stop))
        this->enqueue(instruction->endAddress());
}

} // namespace REDasm
