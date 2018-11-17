#include "metaarm.h"
#include "metaarm_emulator.h"
#include "metaarm_algorithm.h"

namespace REDasm {

MetaARMAssembler::MetaARMAssembler(): AssemblerPlugin()
{
    m_armassembler = new ARMAssembler();
    m_thumbassembler = new ARMThumbAssembler();
    m_assembler = m_armassembler;
}

MetaARMAssembler::~MetaARMAssembler()
{
    delete m_thumbassembler;
    delete m_armassembler;
}

u32 MetaARMAssembler::flags() const { return AssemblerFlags::HasEmulator; }
const char *MetaARMAssembler::name() const { return "Meta ARM"; }
Emulator *MetaARMAssembler::createEmulator(DisassemblerAPI *disassembler) const { return new MetaARMEmulator(disassembler); }
Printer *MetaARMAssembler::createPrinter(DisassemblerAPI *disassembler) const { return new MetaARMPrinter(m_armassembler->handle(), disassembler); }
AssemblerAlgorithm *MetaARMAssembler::createAlgorithm(DisassemblerAPI *disassembler) { return new MetaARMAlgorithm(disassembler, this); }
bool MetaARMAssembler::decode(BufferRef& buffer, const InstructionPtr &instruction) { return m_assembler->decode(buffer, instruction); }
bool MetaARMAssembler::isPC(const Operand &op) const { return m_armassembler->isPC(op); }
bool MetaARMAssembler::isLR(const Operand &op) const { return m_armassembler->isLR(op); }
bool MetaARMAssembler::isARMMode() const { return m_assembler == m_armassembler; }
bool MetaARMAssembler::isTHUMBMode() const { return m_assembler == m_thumbassembler; }
void MetaARMAssembler::switchToARM() { m_assembler = m_armassembler; }
void MetaARMAssembler::switchToThumb() { m_assembler = m_thumbassembler; }

} // namespace REDasm
