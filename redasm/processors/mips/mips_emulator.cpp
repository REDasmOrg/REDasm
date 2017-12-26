#include "mips_emulator.h"
#include <capstone.h>

namespace REDasm {

MIPSEmulator::MIPSEmulator(DisassemblerFunctions *disassembler): VMIL::Emulator(disassembler)
{
    VMIL_TRANSLATE_OPCODE(MIPS_INS_LUI, LUI);
    VMIL_TRANSLATE_OPCODE(MIPS_INS_NOP, NOP);
    VMIL_TRANSLATE_OPCODE(MIPS_INS_SLL, SLL);
    VMIL_TRANSLATE_OPCODE(MIPS_INS_SRL, SRL);
}

void MIPSEmulator::translateLUI(const InstructionPtr &instruction, VMIL::VMILInstructionPtr &vminstruction, VMIL::VMILInstructionList &vminstructions) const
{
    vminstruction = this->createInstruction(instruction, VMIL::Str);
    vminstruction->op(instruction->op(0));
    vminstruction->op(instruction->op(1));
    vminstructions.push_back(vminstruction);

    if(instruction->size == 4)
    {
        vminstruction = this->createInstruction(instruction, VMIL::Lsh, VMIL_INSTRUCTION_I(vminstructions));
        vminstruction->op(instruction->op(0));
        vminstruction->op(instruction->op(0));
        vminstruction->imm(4);
        vminstructions.push_back(vminstruction);
    }
}

void MIPSEmulator::translateNOP(const InstructionPtr &instruction, VMIL::VMILInstructionPtr &vminstruction, VMIL::VMILInstructionList &vminstructions) const
{
    vminstruction = this->createInstruction(instruction, VMIL::Nop);
    vminstructions.push_back(vminstruction);
}

void MIPSEmulator::translateSLL(const InstructionPtr &instruction, VMIL::VMILInstructionPtr &vminstruction, VMIL::VMILInstructionList &vminstructions) const
{
    vminstruction = this->createInstruction(instruction, VMIL::Lsh);
    vminstruction->op(instruction->op(0));
    vminstruction->op(instruction->op(1));
    vminstruction->op(instruction->op(2));
    vminstructions.push_back(vminstruction);
}

void MIPSEmulator::translateSRL(const InstructionPtr &instruction, VMIL::VMILInstructionPtr &vminstruction, VMIL::VMILInstructionList &vminstructions) const
{
    vminstruction = this->createInstruction(instruction, VMIL::Rsh);
    vminstruction->op(instruction->op(0));
    vminstruction->op(instruction->op(1));
    vminstruction->op(instruction->op(2));
    vminstructions.push_back(vminstruction);
}

} // namespace REDasm
