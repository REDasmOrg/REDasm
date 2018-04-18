#include "metaarm_emulator.h"
#include <capstone.h>

namespace REDasm {

MetaARMEmulator::MetaARMEmulator(DisassemblerAPI *disassembler): VMIL::Emulator(disassembler)
{
    VMIL_TRANSLATE_OPCODE(ARM_INS_LDR, Ldr);
    VMIL_TRANSLATE_OPCODE(ARM_INS_B, Branch);
    VMIL_TRANSLATE_OPCODE(ARM_INS_BX, Branch);
}

bool MetaARMEmulator::emulate(const InstructionPtr &instruction)
{
    return VMIL::Emulator::emulate(instruction);
}

void MetaARMEmulator::translateLdr(const InstructionPtr &instruction, VMIL::VMILInstructionPtr &vminstruction, VMIL::VMILInstructionList &vminstructions) const
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

void MetaARMEmulator::translateBranch(const InstructionPtr &instruction, VMIL::VMILInstructionPtr &vminstruction, VMIL::VMILInstructionList &vminstructions) const
{
    /*
    if(instruction->id == ARM_INS_BX)
    {
        vminstruction = VMIL::emitAnd(instruction, VMIL_INSTRUCTION_I(vminstructions));
        vminstruction->op(instruction->op(0));
        vminstruction->op(instruction->op(0));
        vminstruction->imm(-1 ^ 3);
        vminstructions.push_back(vminstruction);
    }
    */

    vminstruction = VMIL::emitJcc(instruction, VMIL_INSTRUCTION_I(vminstructions));
    vminstruction->imm(VMIL_TRUE);
    vminstruction->op(instruction->op(0));
    vminstruction->target_idx = 0;
    vminstructions.push_back(vminstruction);
}

} // namespace REDasm
