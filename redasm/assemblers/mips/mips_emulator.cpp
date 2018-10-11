#include "mips_emulator.h"
#include <capstone.h>

namespace REDasm {

MIPSEmulator::MIPSEmulator(DisassemblerAPI *disassembler): Emulator(disassembler)
{
    EMULATE_INSTRUCTION(MIPS_INS_LB,  &MIPSEmulator::emulateLxx);
    EMULATE_INSTRUCTION(MIPS_INS_LBU, &MIPSEmulator::emulateLxx);
    EMULATE_INSTRUCTION(MIPS_INS_LH,  &MIPSEmulator::emulateLxx);
    EMULATE_INSTRUCTION(MIPS_INS_LWR, &MIPSEmulator::emulateLxx);
    EMULATE_INSTRUCTION(MIPS_INS_LWL, &MIPSEmulator::emulateLxx);
    EMULATE_INSTRUCTION(MIPS_INS_LW,  &MIPSEmulator::emulateLxx);
    EMULATE_INSTRUCTION(MIPS_INS_LHU, &MIPSEmulator::emulateLxx);

    EMULATE_INSTRUCTION(MIPS_INS_SB,  &MIPSEmulator::emulateSxx);
    EMULATE_INSTRUCTION(MIPS_INS_SH,  &MIPSEmulator::emulateSxx);
    EMULATE_INSTRUCTION(MIPS_INS_SWL, &MIPSEmulator::emulateSxx);
    EMULATE_INSTRUCTION(MIPS_INS_SW,  &MIPSEmulator::emulateSxx);
    EMULATE_INSTRUCTION(MIPS_INS_SWR, &MIPSEmulator::emulateSxx);

    EMULATE_INSTRUCTION(MIPS_INS_ADD,   &MIPSEmulator::emulateMath);
    EMULATE_INSTRUCTION(MIPS_INS_ADDI,  &MIPSEmulator::emulateMath);
    EMULATE_INSTRUCTION(MIPS_INS_ADDIU, &MIPSEmulator::emulateMath);
    EMULATE_INSTRUCTION(MIPS_INS_ADDU,  &MIPSEmulator::emulateMath);
    EMULATE_INSTRUCTION(MIPS_INS_SUB,   &MIPSEmulator::emulateMath);
    EMULATE_INSTRUCTION(MIPS_INS_SUBU,  &MIPSEmulator::emulateMath);
    EMULATE_INSTRUCTION(MIPS_INS_MUL,   &MIPSEmulator::emulateMath);
    EMULATE_INSTRUCTION(MIPS_INS_AND,   &MIPSEmulator::emulateMath);
    EMULATE_INSTRUCTION(MIPS_INS_ANDI,  &MIPSEmulator::emulateMath);
    EMULATE_INSTRUCTION(MIPS_INS_OR,    &MIPSEmulator::emulateMath);
    EMULATE_INSTRUCTION(MIPS_INS_ORI,   &MIPSEmulator::emulateMath);
    EMULATE_INSTRUCTION(MIPS_INS_XOR,   &MIPSEmulator::emulateMath);
    EMULATE_INSTRUCTION(MIPS_INS_XORI,  &MIPSEmulator::emulateMath);
    EMULATE_INSTRUCTION(MIPS_INS_SLL,   &MIPSEmulator::emulateMath);
    EMULATE_INSTRUCTION(MIPS_INS_SLLV,  &MIPSEmulator::emulateMath);
    EMULATE_INSTRUCTION(MIPS_INS_SRL,   &MIPSEmulator::emulateMath);
    EMULATE_INSTRUCTION(MIPS_INS_SRLV,  &MIPSEmulator::emulateMath);
    EMULATE_INSTRUCTION(MIPS_INS_SRAV,  &MIPSEmulator::emulateMath);
    EMULATE_INSTRUCTION(MIPS_INS_LUI,   &MIPSEmulator::emulateLui);

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

void MIPSEmulator::emulateLxx(const InstructionPtr &instruction)
{
    size_t size = 0;

    if((instruction->id == MIPS_INS_LB) || (instruction->id == MIPS_INS_LBU))
        size = sizeof(u8);
    else if((instruction->id == MIPS_INS_LH) || (instruction->id == MIPS_INS_LHU))
        size = sizeof(u16);
    else if((instruction->id == MIPS_INS_LW) || (instruction->id == MIPS_INS_LWL) || (instruction->id == MIPS_INS_LWR))
        size = sizeof(u32);
    else
    {
        this->unhandled(instruction);
        return;
    }

    address_t regvalue = 0, value = 0;
    const Operand &op1 = instruction->op(0), &op2 = instruction->op(1);

    if(!this->read(op2, &value))
        return;

    value += op2.disp.displacement;

    if(!this->readMemory(value, size, &value))
        return;

    this->read(op1, &regvalue);

    if(instruction->id == MIPS_INS_LWL)
        regvalue = (regvalue & 0xFFFF) | (value & 0xFFFF0000);
    else if(instruction->id == MIPS_INS_LWR)
        regvalue = (regvalue & 0xFFFF) | (value & 0x0000FFFF);
    else
        regvalue = value;

    this->write(op1, regvalue);
}

void MIPSEmulator::emulateSxx(const InstructionPtr &instruction)
{
    size_t size = 0;

    if((instruction->id == MIPS_INS_SB))
        size = sizeof(u8);
    else if((instruction->id == MIPS_INS_SH))
        size = sizeof(u16);
    else if((instruction->id == MIPS_INS_SW) || (instruction->id == MIPS_INS_SWL) || (instruction->id == MIPS_INS_SWR))
        size = sizeof(u32);
    else
    {
        this->unhandled(instruction);
        return;
    }

    address_t regvalue = 0, memloc = 0, memvalue = 0;
    const Operand &op1 = instruction->op(0), &op2 = instruction->op(1);

    if(!this->read(op1, &regvalue) || !this->read(op2, &memloc))
        return;

    this->readMemory(memloc, size, &memvalue);

    if(instruction->id == MIPS_INS_SWL)
        regvalue = (regvalue & 0xFFFF) | (memvalue & 0xFFFF0000);
    else if(instruction->id == MIPS_INS_SWR)
        regvalue = (regvalue & 0xFFFF) | (memvalue & 0x0000FFFF);

    this->writeMemory(memloc, regvalue);
}

} // namespace REDasm
