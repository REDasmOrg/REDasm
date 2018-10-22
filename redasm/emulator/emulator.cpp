#include "emulator.h"
#include "../plugins/format.h"

namespace REDasm {

Emulator::Emulator(DisassemblerAPI *disassembler): EmulatorBase(disassembler) { }

void Emulator::mathOp(const InstructionPtr &instruction, int opdest, int opsrc1, int opsrc2)
{
    u64 src1 = 0, src2 = 0;

    if(!this->read(instruction->op(opsrc1), &src1))
    {
        REDasm::log("Cannot read operand 1 @ " + REDasm::hex(instruction->address, m_disassembler->format()->bits(), false));
        return;
    }

    if(!this->read(instruction->op(opsrc2), &src2))
    {
        REDasm::log("Cannot read operand 2 @ " + REDasm::hex(instruction->address, m_disassembler->format()->bits(), false));
        return;
    }

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

void Emulator::moveOp(const InstructionPtr &instruction, int opdest, int opsrc)
{
    u64 value = 0;

    if(!this->read(instruction->op(opsrc), &value))
        return;

    this->write(instruction->op(opdest), value);
}

bool Emulator::read(const Operand &op, u64* value)
{
    if(op.is(OperandTypes::Displacement))
    {
        if(this->computeDisplacement(op.disp, value))
            return true;

        REDasm::log("Error reading displacement operand " + std::to_string(op.index));
        this->fail();
        return false;
    }

    if(op.is(OperandTypes::Register))
    {
        *value = this->regRead(op.reg.r);
        return true;
    }

    if(op.is(OperandTypes::Memory))
    {
        if(this->readMemory(op.u_value, op.size, value))
            return true;

        REDasm::log("Error reading memory operand " + std::to_string(op.index));
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
        if(!this->computeDisplacement(op.disp, &value))
            this->fail();
    }
    else if(op.is(OperandTypes::Memory))
        this->writeMemory(op.u_value, value);
    else if(op.is(OperandTypes::Register))
        this->regWrite(op.reg.r, value);
    else
        this->fail();
}

} // namespace REDasm
