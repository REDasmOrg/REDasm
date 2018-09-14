#include "controlflow.h"

namespace REDasm {

DisassemblerControlFlow::DisassemblerControlFlow(DisassemblerAPI *disassembler, AssemblerPlugin *assemblerplugin): DisassemblerAlgorithm(disassembler, assemblerplugin)
{

}

void DisassemblerControlFlow::onDisassembled(const InstructionPtr &instruction, u32 result)
{
    DisassemblerAlgorithm::onDisassembled(instruction, result);

    if(result == DisassemblerAlgorithm::FAIL)
        return;

    for(address_t target : instruction->targets)
        this->push(target);

    if(!instruction->is(InstructionTypes::Stop))
        this->push(instruction->endAddress());
}

} // namespace REDasm
