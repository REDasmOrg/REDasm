#ifndef EMULATOR_TYPE_H
#define EMULATOR_TYPE_H

#include "emulator_alu.h"
#include "../redasm.h"

namespace REDasm {

template<typename T> class EmulatorT: public EmulatorALU<T>
{
    public:
        EmulatorT(DisassemblerAPI* disassembler);
        virtual bool read(const Operand& op, u64* value);

    protected:
        void moveOp(const InstructionPtr& instruction, int opdest, int opsrc);
};

} // namespace REDasm

#include "emulator_type.cpp"

#endif // EMULATOR_TYPE_H
