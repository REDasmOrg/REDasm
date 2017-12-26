#include "mips_emulator.h"
#include <capstone.h>

namespace REDasm {

MIPSEmulator::MIPSEmulator(DisassemblerFunctions *disassembler): VMIL::Emulator(disassembler)
{
    VMIL_TRANSLATE_OPCODE(MIPS_INS_LB,  Lxx);
    VMIL_TRANSLATE_OPCODE(MIPS_INS_LH,  Lxx);
    VMIL_TRANSLATE_OPCODE(MIPS_INS_LWL, Lxx);
    VMIL_TRANSLATE_OPCODE(MIPS_INS_LW,  Lxx);
    VMIL_TRANSLATE_OPCODE(MIPS_INS_LBU, Lxx);
    VMIL_TRANSLATE_OPCODE(MIPS_INS_LHU, Lxx);
    VMIL_TRANSLATE_OPCODE(MIPS_INS_LWR, Lxx);

    VMIL_TRANSLATE_OPCODE(MIPS_INS_SB,  Sxx);
    VMIL_TRANSLATE_OPCODE(MIPS_INS_SH,  Sxx);
    VMIL_TRANSLATE_OPCODE(MIPS_INS_SWL, Sxx);
    VMIL_TRANSLATE_OPCODE(MIPS_INS_SW,  Sxx);
    VMIL_TRANSLATE_OPCODE(MIPS_INS_SWR, Sxx);

    VMIL_TRANSLATE_OPCODE(MIPS_INS_LUI, LUI); // Handles macros
    VMIL_TRANSLATE_OPCODE(MIPS_INS_NOP, NOP);
    VMIL_TRANSLATE_OPCODE(MIPS_INS_SLL, SLL);
    VMIL_TRANSLATE_OPCODE(MIPS_INS_SRL, SRL);
}

void MIPSEmulator::translateLxx(const InstructionPtr &instruction, VMIL::VMILInstructionPtr &vminstruction, VMIL::VMILInstructionList &vminstructions) const
{
    VMIL::vmilregister_t r = this->createMemDisp(instruction, 1, vminstructions);
    vminstruction = this->createInstruction(instruction, VMIL::Opcodes::Ldm, VMIL_INSTRUCTION_I(vminstructions));

    if((instruction->id == MIPS_INS_LWL) || (instruction->id == MIPS_INS_LWR))
        vminstruction->reg(VMIL_REGISTER(1)); // Temporary register for HI/LO part management
    else
        vminstruction->op(instruction->op(0));

    vminstruction->reg(VMIL_REGISTER(r));
    vminstructions.push_back(vminstruction);

    switch(instruction->id)
    {
        case MIPS_INS_LB:
        case MIPS_INS_LBU:
            vminstruction->op_size(1, OperandSizes::Byte);
            break;

        case MIPS_INS_LH:
        case MIPS_INS_LHU:
            vminstruction->op_size(1, OperandSizes::Word);
            break;

        case MIPS_INS_LW:
        case MIPS_INS_LWL:
        case MIPS_INS_LWR:
            vminstruction->op_size(1, OperandSizes::Dword);
            break;

        default:
            break;
    }

    if((instruction->id == MIPS_INS_LWL) || (instruction->id == MIPS_INS_LWR))
    {
        vminstruction = this->createInstruction(instruction, VMIL::Opcodes::And, VMIL_INSTRUCTION_I(vminstructions));
        vminstruction->reg(VMIL_REGISTER(1));
        vminstruction->reg(VMIL_REGISTER(1));
        vminstruction->imm((instruction->id == MIPS_INS_LWL) ? 0x0000FFFF : 0xFFFF0000);
        vminstructions.push_back(vminstruction);

        vminstruction = this->createInstruction(instruction, VMIL::Opcodes::Or, VMIL_INSTRUCTION_I(vminstructions));
        vminstruction->op(instruction->op(0));
        vminstruction->op(instruction->op(0));
        vminstruction->reg(VMIL_REGISTER(1));
        vminstructions.push_back(vminstruction);
    }
}

void MIPSEmulator::translateSxx(const InstructionPtr &instruction, VMIL::VMILInstructionPtr &vminstruction, VMIL::VMILInstructionList &vminstructions) const
{
    if((instruction->id == MIPS_INS_SWL) || (instruction->id == MIPS_INS_SWR))
    {
        vminstruction = this->createInstruction(instruction, VMIL::Opcodes::Str, VMIL_INSTRUCTION_I(vminstructions));
        vminstruction->reg(VMIL_REGISTER(1));
        vminstruction->op(instruction->op(0));
        vminstructions.push_back(vminstruction);

        vminstruction = this->createInstruction(instruction, VMIL::Opcodes::And, VMIL_INSTRUCTION_I(vminstructions));
        vminstruction->reg(VMIL_REGISTER(1));
        vminstruction->reg(VMIL_REGISTER(1));
        vminstruction->imm((instruction->id == MIPS_INS_LWL) ? 0x0000FFFF : 0xFFFF0000);
        vminstructions.push_back(vminstruction);
    }

    VMIL::vmilregister_t r = this->createMemDisp(instruction, 1, vminstructions);
    vminstruction = this->createInstruction(instruction, VMIL::Opcodes::Stm, VMIL_INSTRUCTION_I(vminstructions));
    vminstruction->reg(VMIL_REGISTER(r));

    if((instruction->id == MIPS_INS_SWL) || (instruction->id == MIPS_INS_SWR))
        vminstruction->reg(VMIL_REGISTER(1)); // Temporary register for HI/LO part management
    else
        vminstruction->op(instruction->op(0));

    vminstructions.push_back(vminstruction);

    switch(instruction->id)
    {
        case MIPS_INS_SB:
            vminstruction->op_size(1, OperandSizes::Byte);
            break;

        case MIPS_INS_SH:
            vminstruction->op_size(1, OperandSizes::Word);
            break;

        case MIPS_INS_SW:
        case MIPS_INS_SWL:
        case MIPS_INS_SWR:
            vminstruction->op_size(1, OperandSizes::Dword);
            break;

        default:
            break;
    }
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
        vminstruction->imm(16);
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
