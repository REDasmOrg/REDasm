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
    vminstruction = VMIL::emitDef(instruction, VMIL_INSTRUCTION_I(vminstructions));
    vminstruction->op(instruction->op(0));
    vminstructions.push_back(vminstruction);

    vminstruction = VMIL::emitLdm(instruction, VMIL_INSTRUCTION_I(vminstructions));
    vminstruction->op(instruction->op(0));
    vminstruction->op(instruction->op(1));
    vminstruction->op(1).type |= OperandTypes::NoDereference;
    vminstruction->op_size(1, OperandSizes::Dword);
    vminstructions.push_back(vminstruction);
}

void ARMEmulator::translateBranch(const InstructionPtr &instruction, VMIL::VMILInstructionPtr &vminstruction, VMIL::VMILInstructionList &vminstructions) const
{
    if(instruction->id == ARM_INS_BX)
    {
        /*
         * From ARM Documentation:
         *  Bits 0 and 1 of the address of any ARM instruction are ignored because these bits refer to the halfword and byte part of the address.
         */

        vminstruction = VMIL::emitAnd(instruction, VMIL_INSTRUCTION_I(vminstructions));
        vminstruction->op(instruction->op(0));
        vminstruction->op(instruction->op(0));
        vminstruction->imm(-1 ^ 3);
        vminstructions.push_back(vminstruction);
    }

    vminstruction = VMIL::emitJcc(instruction, VMIL_INSTRUCTION_I(vminstructions));
    vminstruction->imm(VMIL_TRUE);
    vminstruction->op(instruction->op(0));
    vminstruction->target_idx = 0;
    vminstructions.push_back(vminstruction);
}

} // namespace REDasm
