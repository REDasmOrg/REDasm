#include "linearsweep.h"

namespace REDasm {

DisassemblerLinearSweep::DisassemblerLinearSweep(DisassemblerAPI *disassembler, AssemblerPlugin *assemblerplugin): DisassemblerAlgorithm(disassembler, assemblerplugin) { }
void DisassemblerLinearSweep::onDecodeFailed(const InstructionPtr &instruction) { this->enqueue(instruction->address + 1); }

void DisassemblerLinearSweep::onDecoded(const InstructionPtr &instruction)
{
    DisassemblerAlgorithm::onDecoded(instruction);
    this->enqueue(instruction->endAddress());
}

} // namespace REDasm
