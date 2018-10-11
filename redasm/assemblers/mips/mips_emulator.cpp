#include "mips_emulator.h"
#include <capstone.h>

namespace REDasm {

MIPSEmulator::MIPSEmulator(DisassemblerAPI *disassembler): Emulator(disassembler)
{
    //VMIL_TRANSLATE_OPCODE(MIPS_INS_LB,  Lxx);
    //VMIL_TRANSLATE_OPCODE(MIPS_INS_LH,  Lxx);
    //VMIL_TRANSLATE_OPCODE(MIPS_INS_LWL, Lxx);
    //VMIL_TRANSLATE_OPCODE(MIPS_INS_LW,  Lxx);
    //VMIL_TRANSLATE_OPCODE(MIPS_INS_LBU, Lxx);
    //VMIL_TRANSLATE_OPCODE(MIPS_INS_LHU, Lxx);
    //VMIL_TRANSLATE_OPCODE(MIPS_INS_LWR, Lxx);

    //VMIL_TRANSLATE_OPCODE(MIPS_INS_SB,  Sxx);
    //VMIL_TRANSLATE_OPCODE(MIPS_INS_SH,  Sxx);
    //VMIL_TRANSLATE_OPCODE(MIPS_INS_SWL, Sxx);
    //VMIL_TRANSLATE_OPCODE(MIPS_INS_SW,  Sxx);
    //VMIL_TRANSLATE_OPCODE(MIPS_INS_SWR, Sxx);

    EMULATE_INSTRUCTION(MIPS_INS_ADD, &MIPSEmulator::emulateMath);
    EMULATE_INSTRUCTION(MIPS_INS_ADDI,&MIPSEmulator::emulateMath);
    EMULATE_INSTRUCTION(MIPS_INS_ADDIU, &MIPSEmulator::emulateMath);
    EMULATE_INSTRUCTION(MIPS_INS_ADDU, &MIPSEmulator::emulateMath);
    EMULATE_INSTRUCTION(MIPS_INS_SUB, &MIPSEmulator::emulateMath);
    EMULATE_INSTRUCTION(MIPS_INS_SUBU, &MIPSEmulator::emulateMath);
    EMULATE_INSTRUCTION(MIPS_INS_MUL, &MIPSEmulator::emulateMath);
    EMULATE_INSTRUCTION(MIPS_INS_AND, &MIPSEmulator::emulateMath);
    EMULATE_INSTRUCTION(MIPS_INS_ANDI, &MIPSEmulator::emulateMath);
    EMULATE_INSTRUCTION(MIPS_INS_OR, &MIPSEmulator::emulateMath);
    EMULATE_INSTRUCTION(MIPS_INS_ORI, &MIPSEmulator::emulateMath);
    EMULATE_INSTRUCTION(MIPS_INS_XOR, &MIPSEmulator::emulateMath);
    EMULATE_INSTRUCTION(MIPS_INS_XORI, &MIPSEmulator::emulateMath);
    EMULATE_INSTRUCTION(MIPS_INS_SLL, &MIPSEmulator::emulateMath);
    EMULATE_INSTRUCTION(MIPS_INS_SLLV, &MIPSEmulator::emulateMath);
    EMULATE_INSTRUCTION(MIPS_INS_SRL, &MIPSEmulator::emulateMath);
    EMULATE_INSTRUCTION(MIPS_INS_SRLV, &MIPSEmulator::emulateMath);
    EMULATE_INSTRUCTION(MIPS_INS_SRAV, &MIPSEmulator::emulateMath);
    EMULATE_INSTRUCTION(MIPS_INS_LUI, &MIPSEmulator::emulateLui);

    //EMULATE_INSTRUCTION(MIPS_INS_MULT, &MIPSEmulator::emulateMath);
    //EMULATE_INSTRUCTION(MIPS_INS_MULTU, &MIPSEmulator::emulateMath);
    //EMULATE_INSTRUCTION(MIPS_INS_DIV, &MIPSEmulator::emulateMath);
    //EMULATE_INSTRUCTION(MIPS_INS_DIVU, &MIPSEmulator::emulateMath);
}

bool MIPSEmulator::emulate(const InstructionPtr &instruction)
{
    this->regWrite(MIPS_REG_ZERO, 0); // Initialize $zero
    return Emulator::emulate(instruction);
}

void MIPSEmulator::emulateMath(const InstructionPtr &instruction) { this->mathOp(instruction, 0, 1, 2); }

void MIPSEmulator::emulateLui(const InstructionPtr &instruction)
{
    u64 value = 0;

    if(!this->read(instruction->op(1), &value))
        return;

    this->write(instruction->op(0), value << 16);
}

/*
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
*/

} // namespace REDasm
