#ifndef EMULATOR_H
#define EMULATOR_H

#include "emulatorbase.h"

namespace REDasm {

class Emulator: public EmulatorBase
{
    public:
        Emulator(DisassemblerAPI* disassembler);

    protected:
        void mathOp(const InstructionPtr& instruction, int opdest, int opsrc1, int opsrc2);
        void mathOp(const InstructionPtr& instruction, int opdest, int opsrc);
        bool read(const Operand& op, u64 *value);
        void write(const Operand& op, u64 value);
};

} // namespace REDasm

#endif // EMULATOR_H
