#include "metaarm_emulator.h"
#include <capstone.h>

namespace REDasm {

MetaARMEmulator::MetaARMEmulator(DisassemblerAPI *disassembler): Emulator(disassembler)
{
}

void MetaARMEmulator::emulateLdr(const InstructionPtr &instruction)
{
    RE_UNUSED(instruction);
}

} // namespace REDasm
