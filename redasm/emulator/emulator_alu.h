#ifndef EMULATOR_ALU_H
#define EMULATOR_ALU_H

#include "emulator_base.h"

namespace REDasm {

template<typename T> class EmulatorALU: public EmulatorBase<T>
{
    private:
        typedef typename std::make_signed<T>::type ST;
        enum { CarryFlag = 0 };

    public:
        EmulatorALU(DisassemblerAPI* disassembler);
        virtual bool displacement(const Operand& op, u64* value);
        bool hasCarry() const;

    protected:
        void aluOp(const InstructionPtr& instruction, size_t opdest, size_t opsrc1, size_t opsrc2);
        void aluOp(const InstructionPtr& instruction, size_t opdest, size_t opsrc);

    private:
        T aluAdd(T src1, T src2);
        T aluSub(T src1, T src2);
        T aluMul(T src1, T src2);
        T aluDiv(T src1, T src2);

    private:
        void carry(bool set = true);
};

} // namespace REDasm

#include "emulator_alu.cpp"

#endif // EMULATOR_ALU_H
