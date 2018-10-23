#ifndef METAARM_EMULATOR_H
#define METAARM_EMULATOR_H

#include "../../emulator/emulator_type.h"

namespace REDasm {

class MetaARMEmulator: public EmulatorT<u32>
{
    private:
        enum { CarryFlag = 0 };

    public:
        MetaARMEmulator(DisassemblerAPI* disassembler);
        virtual void emulate(const InstructionPtr& instruction);

    private:
        void emulateMath(const InstructionPtr& instruction);
        void emulateMov(const InstructionPtr& instruction);
        void emulateLdr(const InstructionPtr& instruction);
        void emulateStr(const InstructionPtr& instruction);
};

} // namespace REDasm

#endif // METAARM_EMULATOR_H
