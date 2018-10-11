#include "emulator.h"
#include "../plugins/format.h"

namespace REDasm {

Emulator::Emulator(DisassemblerAPI *disassembler): EmulatorBase(disassembler) { }

void Emulator::mathOp(const InstructionPtr &instruction, int opdest, int opsrc1, int opsrc2)
{
    u64 src1 = 0, src2 = 0;

    if(!this->read(instruction->op(opsrc1), &src1))
        return;

    if(!this->read(instruction->op(opsrc2), &src2))
        return;

    if(instruction->is(InstructionTypes::Add))
        this->write(instruction->op(opdest), src1 + src2);
    else if(instruction->is(InstructionTypes::Sub))
        this->write(instruction->op(opdest), src1 - src2);
    else if(instruction->is(InstructionTypes::Mul))
        this->write(instruction->op(opdest), src1 * src2);
    else if(instruction->is(InstructionTypes::Div))
        this->write(instruction->op(opdest), src1 / src2);
    else if(instruction->is(InstructionTypes::Mod))
        this->write(instruction->op(opdest), src1 % src2);
    else if(instruction->is(InstructionTypes::And))
        this->write(instruction->op(opdest), src1 & src2);
    else if(instruction->is(InstructionTypes::Or))
        this->write(instruction->op(opdest), src1 | src2);
    else if(instruction->is(InstructionTypes::Xor))
        this->write(instruction->op(opdest), src1 ^ src2);
    else if(instruction->is(InstructionTypes::Lsh))
        this->write(instruction->op(opdest), src1 << src2);
    else if(instruction->is(InstructionTypes::Rsh))
        this->write(instruction->op(opdest), src1 >> src2);
    else
        this->unhandled(instruction);
}

void Emulator::mathOp(const InstructionPtr &instruction, int opdest, int opsrc) { this->mathOp(instruction, opdest, opdest, opsrc); }

bool Emulator::read(const Operand &op, u64* value)
{
    if(op.is(OperandTypes::Displacement))
    {
        if(this->computeDisplacement(op.disp, value) && this->readMemory(*value, op.size, value))
            return true;

        this->fail();
        return false;
    }

    if(op.is(OperandTypes::Register))
    {
        if(this->reg(op.reg.r, value))
            return true;

        this->fail();
        return false;
    }

    if(op.is(OperandTypes::Memory))
    {
        if(this->readMemory(op.u_value, op.size, value))
            return true;

        this->fail();
        return false;
    }

    *value = op.u_value;
    return true;
}

void Emulator::write(const Operand &op, u64 value)
{
    if(op.is(OperandTypes::Displacement))
    {
        u64 disp = 0;

        if(this->computeDisplacement(op.disp, &disp))
            this->writeMemory(disp, value);
        else
            this->fail();
    }
    if(op.is(OperandTypes::Memory))
        this->writeMemory(op.u_value, value);
    else if(op.is(OperandTypes::Register))
        this->regWrite(op.reg.r, value);
    else
        this->fail();
}

} // namespace REDasm
