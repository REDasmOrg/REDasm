#include "emulator_alu.h"
#include <type_traits>

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
        dst = src1 + src2;
    else if(instruction->is(InstructionTypes::Sub))
        dst = src1 - src2;
    else if(instruction->is(InstructionTypes::Mul))
        dst = src1 * src2;
    else if(instruction->is(InstructionTypes::Div))
    {
        if(!src2)
        {
            REDasm::log("Division by zero @ " + REDasm::hex(instruction->address));
            this->fail();
            return;
        }

        dst = src1 / src2;
    }
    else if(instruction->is(InstructionTypes::Mod))
        dst = src1 % src2;
    else if(instruction->is(InstructionTypes::And))
        dst = src1 & src2;
    else if(instruction->is(InstructionTypes::Or))
        dst = src1 | src2;
    else if(instruction->is(InstructionTypes::Xor))
        dst = src1 ^ src2;
    else if(instruction->is(InstructionTypes::Lsh))
        dst = src1 << src2;
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
template<typename T> void EmulatorALU<T>::carry(bool set) { this->flag(EmulatorALU::CarryFlag, set); }
template<typename T> void EmulatorALU<T>::overflow(bool set) { this->flag(EmulatorALU::OverflowFlag, set); }

} // namespace REDasm
