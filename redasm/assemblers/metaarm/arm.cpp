#include "arm.h"
#include "arm_common.h"
#include "metaarm_emulator.h"

namespace REDasm {

ARMAssembler::ARMAssembler(): ARMCommonAssembler<CS_ARCH_ARM, CS_MODE_ARM>()
{
    REGISTER_INSTRUCTION(ARM_INS_LDR, &ARMAssembler::setOp2_32);
}

const char *ARMAssembler::name() const { return "ARM"; }
u32 ARMAssembler::flags() const { return AssemblerFlags::HasEmulator; }
Emulator *ARMAssembler::createEmulator(DisassemblerAPI *disassembler) const { return new MetaARMEmulator(disassembler); }
Printer *ARMAssembler::createPrinter(DisassemblerAPI *disassembler) const { return new MetaARMPrinter(m_cshandle, disassembler); }
void ARMAssembler::setOp2_32(const InstructionPtr &instruction) const { instruction->op(1).size = sizeof(u32); }

} // namespace REDasm
