#include "arm.h"
#include "arm_common.h"
#include "metaarm_emulator.h"

namespace REDasm {

ARMAssembler::ARMAssembler(): CapstoneAssemblerPlugin<CS_ARCH_ARM, CS_MODE_ARM>()
{

}

const char *ARMAssembler::name() const
{
    return "ARM";
}

u32 ARMAssembler::flags() const
{
    return AssemblerFlags::HasVMIL | AssemblerFlags::EmulateVMIL;
}

bool ARMAssembler::decode(Buffer buffer, const InstructionPtr &instruction)
{
    if(!CapstoneAssemblerPlugin<CS_ARCH_ARM, CS_MODE_ARM>::decode(buffer, instruction))
        return false;

    return ARMCommon::decode(instruction);
}

VMIL::Emulator *ARMAssembler::createEmulator(DisassemblerAPI *disassembler) const
{
    return new MetaARMEmulator(disassembler);
}

Printer *ARMAssembler::createPrinter(DisassemblerAPI *disassembler, SymbolTable *symboltable) const
{
     return new MetaARMPrinter(this->_cshandle, disassembler, symboltable);
}

} // namespace REDasm
