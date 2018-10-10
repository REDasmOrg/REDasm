#include "assembler.h"
#include "../format.h"
#include <iomanip>
#include <sstream>

namespace REDasm {

AssemblerPlugin::AssemblerPlugin(): Plugin(), m_endianness(Endianness::LittleEndian) { }
u32 AssemblerPlugin::flags() const { return AssemblerFlags::None; }
Emulator *AssemblerPlugin::createEmulator(DisassemblerAPI *disassembler) const { RE_UNUSED(disassembler); return NULL; }
Printer *AssemblerPlugin::createPrinter(DisassemblerAPI *disassembler) const { return new Printer(disassembler); }

bool AssemblerPlugin::decode(Buffer buffer, const InstructionPtr &instruction)
{
    std::stringstream ss;
    ss << std::hex << std::setfill('0');

    for(u64 i = 0; i < instruction->size; i++)
    {
        u8 b = buffer[i];
        ss << std::setw(2) << static_cast<size_t>(b);
    }

    instruction->bytes = ss.str();
    return false;
}

bool AssemblerPlugin::hasFlag(u32 flag) const { return this->flags() & flag; }
endianness_t AssemblerPlugin::endianness() const { return m_endianness; }
void AssemblerPlugin::setEndianness(endianness_t endianness) { m_endianness = endianness; }

}
