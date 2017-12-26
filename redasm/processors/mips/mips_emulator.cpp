#include "mips_emulator.h"

namespace REDasm {

MIPSEmulator::MIPSEmulator(DisassemblerFunctions *disassembler): VMIL::Emulator(disassembler)
{

}

void MIPSEmulator::translate(const InstructionPtr &instruction, VMIL::VMILInstructionList &vminstructions)
{

}

} // namespace REDasm
