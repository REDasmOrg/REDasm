#include "metaarm.h"
#include "metaarm_emulator.h"

namespace REDasm {

MetaARMAssembler::MetaARMAssembler(): AssemblerPlugin()
{
    m_armassembler = new ARMAssembler();
    m_thumbassembler = new ARMThumbAssembler();
}

MetaARMAssembler::~MetaARMAssembler()
{
    delete m_thumbassembler;
    delete m_armassembler;
}

u32 MetaARMAssembler::flags() const { return m_armassembler->flags(); }
const char *MetaARMAssembler::name() const { return "Meta ARM"; }
Emulator *MetaARMAssembler::createEmulator(DisassemblerAPI *disassembler) const { /* return new MetaARMEmulator(disassembler); */ }
Printer *MetaARMAssembler::createPrinter(DisassemblerAPI *disassembler) const { return new MetaARMPrinter(m_armassembler->handle(), disassembler); }

bool MetaARMAssembler::decodeInstruction(Buffer buffer, const InstructionPtr &instruction)
{
    AssemblerPlugin* assemblerplugin = m_armassembler;

    if(instruction->address & 0x1)
        assemblerplugin = m_thumbassembler;

    return assemblerplugin->decode(buffer, instruction);
}

} // namespace REDasm
