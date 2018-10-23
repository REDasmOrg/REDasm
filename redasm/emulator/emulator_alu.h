#ifndef EMULATOR_ALU_H
#define EMULATOR_ALU_H

#include "emulator_base.h"

namespace REDasm {

template<typename T> class EmulatorALU: public EmulatorBase<T>
{
    private:
        enum { CarryFlag = 0, OverflowFlag };

    public:
        EmulatorALU(DisassemblerAPI* disassembler);
        virtual bool displacement(const Operand& op, u64* value);

    protected:
        void aluOp(const InstructionPtr& instruction, size_t opdest, size_t opsrc1, size_t opsrc2);
        void aluOp(const InstructionPtr& instruction, size_t opdest, size_t opsrc);

    private:
        void carry(bool set = true);
        void overflow(bool set = true);
};

} // namespace REDasm

#include "emulator_alu.cpp"

#endif // EMULATOR_ALU_H
