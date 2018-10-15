#include "linearsweep.h"

namespace REDasm {

LinearSweepAlgorithm::LinearSweepAlgorithm(DisassemblerAPI *disassembler, AssemblerPlugin *assemblerplugin): AssemblerAlgorithm(disassembler, assemblerplugin) { }
void LinearSweepAlgorithm::onDecodeFailed(const InstructionPtr &instruction) { this->enqueue(instruction->address + 1); }

void LinearSweepAlgorithm::onDecoded(const InstructionPtr &instruction)
{
    AssemblerAlgorithm::onDecoded(instruction);
    this->enqueue(instruction->endAddress());
}

} // namespace REDasm
