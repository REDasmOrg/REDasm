#include "arm_emulator.h"
#include <capstone.h>

namespace REDasm {

ARMEmulator::ARMEmulator(DisassemblerAPI *disassembler): VMIL::Emulator(disassembler)
{
    VMIL_TRANSLATE_OPCODE(ARM_INS_LDR, Ldr);
    VMIL_TRANSLATE_OPCODE(ARM_INS_B, Branch);
    VMIL_TRANSLATE_OPCODE(ARM_INS_BX, Branch);
}

void ARMEmulator::translateLdr(const InstructionPtr &instruction, VMIL::VMILInstructionPtr &vminstruction, VMIL::VMILInstructionList &vminstructions) const
{
    vminstruction = VMIL::emitStr(instruction, VMIL_INSTRUCTION_I(vminstructions));
    vminstruction->op(instruction->op(0));
    vminstruction->op(instruction->op(1));
    vminstructions.push_back(vminstruction);
}

void ARMEmulator::translateBranch(const InstructionPtr &instruction, VMIL::VMILInstructionPtr &vminstruction, VMIL::VMILInstructionList &vminstructions) const
{
    vminstruction = VMIL::emitJcc(instruction, VMIL_INSTRUCTION_I(vminstructions));
    vminstruction->imm(VMIL_TRUE);
    vminstruction->op(instruction->op(0));
    vminstruction->target_idx = 0;
    vminstructions.push_back(vminstruction);
}

} // namespace REDasm
