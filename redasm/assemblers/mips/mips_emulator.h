#ifndef MIPS_EMULATOR_H
#define MIPS_EMULATOR_H

#include "../../emulator/emulator.h"

namespace REDasm {

class MIPSEmulator: public Emulator
{
    public:
        MIPSEmulator(DisassemblerAPI* disassembler);
        virtual bool emulate(const InstructionPtr &instruction);

    private:
        void emulateAdd(const InstructionPtr& instruction);
        void emulateMath(const InstructionPtr& instruction);
};

} // namespace REDasm

#endif // MIPS_EMULATOR_H
