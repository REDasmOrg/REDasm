#ifndef MIPS_EMULATOR_H
#define MIPS_EMULATOR_H

#include "../../emulator/emulator_type.h"

namespace REDasm {

class MIPSEmulator: public EmulatorT<u32>
{
    public:
        MIPSEmulator(DisassemblerAPI* disassembler);
        virtual void emulate(const InstructionPtr &instruction);

    private:
        void emulateMath(const InstructionPtr& instruction);
        void emulateLui(const InstructionPtr& instruction);
        void emulateLxx(const InstructionPtr& instruction);
        void emulateSxx(const InstructionPtr& instruction);
};

} // namespace REDasm

#endif // MIPS_EMULATOR_H
