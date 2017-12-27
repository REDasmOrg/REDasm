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

    VMIL_TRANSLATE_OPCODE(MIPS_INS_ADD, Math);
    VMIL_TRANSLATE_OPCODE(MIPS_INS_ADDI, Math);
    VMIL_TRANSLATE_OPCODE(MIPS_INS_ADDU, Math);
    VMIL_TRANSLATE_OPCODE(MIPS_INS_ADDIU, Math);
    VMIL_TRANSLATE_OPCODE(MIPS_INS_SUB, Math);
    VMIL_TRANSLATE_OPCODE(MIPS_INS_SUBU, Math);
    VMIL_TRANSLATE_OPCODE(MIPS_INS_MUL, Math);
    VMIL_TRANSLATE_OPCODE(MIPS_INS_MULT, Math);
    VMIL_TRANSLATE_OPCODE(MIPS_INS_MULTU, Math);
    VMIL_TRANSLATE_OPCODE(MIPS_INS_DIV, Math);
    VMIL_TRANSLATE_OPCODE(MIPS_INS_DIVU, Math);

    VMIL_TRANSLATE_OPCODE(MIPS_INS_AND, Bitwise);
    VMIL_TRANSLATE_OPCODE(MIPS_INS_ANDI, Bitwise);
    VMIL_TRANSLATE_OPCODE(MIPS_INS_OR, Bitwise);
    VMIL_TRANSLATE_OPCODE(MIPS_INS_ORI, Bitwise);
    VMIL_TRANSLATE_OPCODE(MIPS_INS_XOR, Bitwise);
    VMIL_TRANSLATE_OPCODE(MIPS_INS_XORI, Bitwise);

    VMIL_TRANSLATE_OPCODE(MIPS_INS_LUI, LUI); // Handles macros
    VMIL_TRANSLATE_OPCODE(MIPS_INS_NOP, NOP);
    VMIL_TRANSLATE_OPCODE(MIPS_INS_SLL, SLL);
    VMIL_TRANSLATE_OPCODE(MIPS_INS_SRL, SRL);
}

void MIPSEmulator::translateLxx(const InstructionPtr &instruction, VMIL::VMILInstructionPtr &vminstruction, VMIL::VMILInstructionList &vminstructions) const
{
    this->emitDisplacement(instruction, 1, vminstructions);
    vminstruction = VMIL::emitLdm(instruction, VMIL_INSTRUCTION_I(vminstructions));

    if((instruction->id == MIPS_INS_LWL) || (instruction->id == MIPS_INS_LWR))
        vminstruction->reg(VMIL_REGISTER(1)); // Temporary register for HI/LO part management
    else
        vminstruction->op(instruction->op(0));

    vminstruction->reg(VMIL_DEFAULT_REGISTER);
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
        vminstruction = VMIL::emitAnd(instruction, VMIL_INSTRUCTION_I(vminstructions));
        vminstruction->reg(VMIL_REGISTER(1));
        vminstruction->reg(VMIL_REGISTER(1));
        vminstruction->imm((instruction->id == MIPS_INS_LWL) ? 0x0000FFFF : 0xFFFF0000);
        vminstructions.push_back(vminstruction);

        vminstruction = VMIL::emitOr(instruction, VMIL_INSTRUCTION_I(vminstructions));
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
        vminstruction = VMIL::emitStr(instruction, VMIL_INSTRUCTION_I(vminstructions));
        vminstruction->reg(VMIL_REGISTER(1));
        vminstruction->op(instruction->op(0));
        vminstructions.push_back(vminstruction);

        vminstruction = VMIL::emitAnd(instruction, VMIL_INSTRUCTION_I(vminstructions));
        vminstruction->reg(VMIL_REGISTER(1));
        vminstruction->reg(VMIL_REGISTER(1));
        vminstruction->imm((instruction->id == MIPS_INS_LWL) ? 0x0000FFFF : 0xFFFF0000);
        vminstructions.push_back(vminstruction);
    }

    this->emitDisplacement(instruction, 1, vminstructions);
    vminstruction = VMIL::emitStm(instruction, VMIL_INSTRUCTION_I(vminstructions));
    vminstruction->reg(VMIL_DEFAULT_REGISTER);

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
    vminstruction = VMIL::emitStr(instruction);
    vminstruction->op(instruction->op(0));
    vminstruction->op(instruction->op(1));
    vminstructions.push_back(vminstruction);

    if(instruction->size == 4)
    {
        vminstruction = VMIL::emitLsh(instruction, VMIL_INSTRUCTION_I(vminstructions));
        vminstruction->op(instruction->op(0));
        vminstruction->op(instruction->op(0));
        vminstruction->imm(16);
        vminstructions.push_back(vminstruction);
    }
}

void MIPSEmulator::translateNOP(const InstructionPtr &instruction, VMIL::VMILInstructionPtr &vminstruction, VMIL::VMILInstructionList &vminstructions) const
{
    vminstruction = VMIL::emitNop(instruction);
    vminstructions.push_back(vminstruction);
}

void MIPSEmulator::translateSLL(const InstructionPtr &instruction, VMIL::VMILInstructionPtr &vminstruction, VMIL::VMILInstructionList &vminstructions) const
{
    vminstruction = VMIL::emitLsh(instruction);
    vminstruction->op(instruction->op(0));
    vminstruction->op(instruction->op(1));
    vminstruction->op(instruction->op(2));
    vminstructions.push_back(vminstruction);
}

void MIPSEmulator::translateSRL(const InstructionPtr &instruction, VMIL::VMILInstructionPtr &vminstruction, VMIL::VMILInstructionList &vminstructions) const
{
    vminstruction = VMIL::emitRsh(instruction);
    vminstruction->op(instruction->op(0));
    vminstruction->op(instruction->op(1));
    vminstruction->op(instruction->op(2));
    vminstructions.push_back(vminstruction);
}

void MIPSEmulator::translateMath(const InstructionPtr &instruction, VMIL::VMILInstructionPtr &vminstruction, VMIL::VMILInstructionList &vminstructions) const
{
    switch(instruction->id)
    {
        case MIPS_INS_ADD:
        case MIPS_INS_ADDI:
        case MIPS_INS_ADDU:
        case MIPS_INS_ADDIU:
            vminstruction = VMIL::emitAdd(instruction);
            break;

        case MIPS_INS_SUB:
        case MIPS_INS_SUBU:
            vminstruction = VMIL::emitSub(instruction);
            break;

        case MIPS_INS_MUL:
        case MIPS_INS_MULT:
        case MIPS_INS_MULTU:
            vminstruction = VMIL::emitMul(instruction);
            break;

        case MIPS_INS_DIV:
        case MIPS_INS_DIVU:
            vminstruction = VMIL::emitDiv(instruction);
            break;

        default:
            return;
    }

    if(instruction->operands.size() == 2)
    {
        vminstruction->op(instruction->op(0));
        vminstruction->op(instruction->op(0));
        vminstruction->op(instruction->op(1));
    }
    else
    {

        vminstruction->op(instruction->op(0));
        vminstruction->op(instruction->op(1));
        vminstruction->op(instruction->op(2));
    }

    vminstructions.push_back(vminstruction);
}

void MIPSEmulator::translateBitwise(const InstructionPtr &instruction, VMIL::VMILInstructionPtr &vminstruction, VMIL::VMILInstructionList &vminstructions) const
{
    switch(instruction->id)
    {
        case MIPS_INS_AND:
        case MIPS_INS_ANDI:
            vminstruction = VMIL::emitAnd(instruction);
            break;

        case MIPS_INS_OR:
        case MIPS_INS_ORI:
            vminstruction = VMIL::emitOr(instruction);
            break;

        case MIPS_INS_XOR:
        case MIPS_INS_XORI:
            vminstruction = VMIL::emitXor(instruction);
            break;

        default:
            return;
    }

    if(instruction->operands.size() == 2)
    {
        vminstruction->op(instruction->op(0));
        vminstruction->op(instruction->op(0));
        vminstruction->op(instruction->op(1));
    }
    else
    {

        vminstruction->op(instruction->op(0));
        vminstruction->op(instruction->op(1));
        vminstruction->op(instruction->op(2));
    }

    vminstructions.push_back(vminstruction);
}

} // namespace REDasm
