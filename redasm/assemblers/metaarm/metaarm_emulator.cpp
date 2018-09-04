#include "metaarm_emulator.h"
#include <capstone.h>

namespace REDasm {

MetaARMEmulator::MetaARMEmulator(DisassemblerAPI *disassembler): VMIL::Emulator(disassembler)
{
    VMIL_TRANSLATE_OPCODE(ARM_INS_LDR, Ldr);
    VMIL_TRANSLATE_OPCODE(ARM_INS_B, Branch);
    VMIL_TRANSLATE_OPCODE(ARM_INS_BX, Bx);
}

void MetaARMEmulator::translateLdr(const InstructionPtr &instruction, VMIL::VMILInstructionPtr &vminstruction, VMIL::VMILInstructionList &vminstructions) const
{
    vminstruction = VMIL::emitDef(instruction, VMIL_INSTRUCTION_I(vminstructions));
    vminstruction->op(instruction->op(0));
    vminstructions.push_back(vminstruction);

    vminstruction = VMIL::emitLdm(instruction, VMIL_INSTRUCTION_I(vminstructions));
    vminstruction->op(instruction->op(0));
    vminstruction->op(instruction->op(1));
    vminstruction->op_size(1, OperandSizes::Dword);
    vminstructions.push_back(vminstruction);
}

void MetaARMEmulator::translateBx(const InstructionPtr &instruction, VMIL::VMILInstructionPtr &vminstruction, VMIL::VMILInstructionList &vminstructions) const
{
    vminstruction = VMIL::emitJcc(instruction, VMIL_INSTRUCTION_I(vminstructions));
    vminstruction->imm(VMIL_TRUE);
    vminstruction->op(instruction->op(0));
    vminstructions.push_back(vminstruction);
}

void MetaARMEmulator::translateBranch(const InstructionPtr &instruction, VMIL::VMILInstructionPtr &vminstruction, VMIL::VMILInstructionList &vminstructions) const
{
    vminstruction = VMIL::emitJcc(instruction, VMIL_INSTRUCTION_I(vminstructions));
    vminstruction->imm(VMIL_TRUE);
    vminstruction->op(instruction->op(0));
    vminstructions.push_back(vminstruction);
}

} // namespace REDasm
