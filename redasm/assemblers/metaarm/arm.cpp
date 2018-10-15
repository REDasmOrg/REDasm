#include "arm.h"
#include "arm_common.h"
#include "metaarm_emulator.h"

namespace REDasm {

ARMAssembler::ARMAssembler(): ARMCommonAssembler<CS_ARCH_ARM, CS_MODE_ARM>() { }
const char *ARMAssembler::name() const { return "ARM"; }
u32 ARMAssembler::flags() const { return AssemblerFlags::HasEmulator; }
Emulator *ARMAssembler::createEmulator(DisassemblerAPI *disassembler) const { return new MetaARMEmulator(disassembler); }
Printer *ARMAssembler::createPrinter(DisassemblerAPI *disassembler) const { return new MetaARMPrinter(m_cshandle, disassembler); }

} // namespace REDasm
