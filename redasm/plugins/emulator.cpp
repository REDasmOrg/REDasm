#include "emulator.h"

namespace REDasm {

Emulator::Emulator(DisassemblerAPI *disassembler): m_disassembler(disassembler) { }

void Emulator::emulate(const InstructionPtr &instruction)
{
    m_currentinstruction = instruction;
    m_dispatcher(instruction->id, instruction);
}

} // namespace REDasm
