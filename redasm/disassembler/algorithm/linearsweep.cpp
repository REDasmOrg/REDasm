#include "linearsweep.h"

namespace REDasm {

DisassemblerLinearSweep::DisassemblerLinearSweep(DisassemblerAPI *disassembler, AssemblerPlugin *assemblerplugin): DisassemblerAlgorithm(disassembler, assemblerplugin)
{

}

void DisassemblerLinearSweep::onDisassembled(const InstructionPtr &instruction, u32 result)
{
    DisassemblerAlgorithm::onDisassembled(instruction, result);

    if(result == DisassemblerAlgorithm::OK)
        this->push(instruction->endAddress() + 1);
    else
        this->push(instruction->address + 1);
}

} // namespace REDasm
