#include "emulator_alu.h"
#include <limits>

// https://wiki.sei.cmu.edu/confluence/display/c/INT32-C.+Ensure+that+operations+on+signed+integers+do+not+result+in+overflow

namespace REDasm {

template<typename T> EmulatorALU<T>::EmulatorALU(DisassemblerAPI *disassembler): EmulatorBase<T>(disassembler) { }

template<typename T> bool EmulatorALU<T>::displacement(const Operand &op, u64 *value)
{
    T tvalue = 0;

    if(!this->displacementT(op.disp, &tvalue))
        return false;

    *value = static_cast<u64>(tvalue);
    return true;
}

template<typename T> bool EmulatorALU<T>::hasCarry() const { return this->flag(EmulatorALU::CarryFlag); }

template<typename T> void EmulatorALU<T>::aluOp(const InstructionPtr &instruction, size_t opdest, size_t opsrc1, size_t opsrc2)
{
    T src1 = 0, src2 = 0;

    if(!this->readOp(instruction->op(opsrc1), &src1))
    {
        REDasm::log("Cannot read operand 1 @ " + REDasm::hex(instruction->address));
        return;
    }

    if(!this->readOp(instruction->op(opsrc2), &src2))
    {
        REDasm::log("Cannot read operand 2 @ " + REDasm::hex(instruction->address));
        return;
    }

    T dst = 0;

    if(instruction->is(InstructionTypes::Add))
        dst = this->aluAdd(src1, src2);
    else if(instruction->is(InstructionTypes::Sub))
        dst = this->aluSub(src1, src2);
    else if(instruction->is(InstructionTypes::Mul))
        dst = this->aluMul(src1, src2);
    else if(instruction->is(InstructionTypes::Div))
    {
        if(!src2)
        {
            REDasm::log("Division by zero @ " + REDasm::hex(instruction->address));
            this->fail();
            return;
        }

        dst = this->aluDiv(src1, src2);
    }
    else if(instruction->is(InstructionTypes::Mod))
    {
        if(!src2)
        {
            REDasm::log("Module by zero @ " + REDasm::hex(instruction->address));
            this->fail();
            return;
        }

        dst = src1 % src2;
    }
    else if(instruction->is(InstructionTypes::And))
        dst = src1 & src2;
    else if(instruction->is(InstructionTypes::Or))
        dst = src1 | src2;
    else if(instruction->is(InstructionTypes::Xor))
        dst = src1 ^ src2;
    else if(instruction->is(InstructionTypes::Lsh))
    {
        if(src2 > bitwidth<T>::value)
        {
            REDasm::log("Invalid left shift @ " + REDasm::hex(instruction->address));
            this->fail();
            return;
        }

        dst = src1 << src2;
    }
    else if(instruction->is(InstructionTypes::Rsh))
        dst = src1 >> src2;
    else
    {
        this->unhandled(instruction);
        return;
    }

    this->writeOp(instruction->op(opdest), dst);
}

template<typename T> void EmulatorALU<T>::aluOp(const InstructionPtr &instruction, size_t opdest, size_t opsrc) { this->aluOp(instruction, opdest, opdest, opsrc); }

template<typename T> T EmulatorALU<T>::aluAdd(T src1, T src2)
{
    this->carry((src1 > (std::numeric_limits<T>::max() - src2)));
    return src1 + src2;
}

template<typename T> T EmulatorALU<T>::aluSub(T src1, T src2)
{
    this->carry((src1 < (std::numeric_limits<T>::min() + src2)));
    return src1 - src2;
}

template<typename T> T EmulatorALU<T>::aluMul(T src1, T src2)
{
    this->carry((src1 > (std::numeric_limits<T>::max() / src2)));
    return src1 * src2;
}

template<typename T> T EmulatorALU<T>::aluDiv(T src1, T src2)
{
    ST ssrc1 = static_cast<ST>(src1);
    ST ssrc2 = static_cast<ST>(src2);
    this->carry((ssrc1 == std::numeric_limits<ST>::min()) && (ssrc2 == -1));
    return src1 / src2;
}

template<typename T> void EmulatorALU<T>::carry(bool set) { this->flag(EmulatorALU::CarryFlag, set); }

} // namespace REDasm
