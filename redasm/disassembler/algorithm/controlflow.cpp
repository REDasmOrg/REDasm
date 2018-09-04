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

    this->push(instruction->endAddress() + 1);
}

} // namespace REDasm
