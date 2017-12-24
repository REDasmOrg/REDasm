#ifndef CHIP8EMULATOR_H
#define CHIP8EMULATOR_H

#include "../../vmil/vmil_emulator.h"

namespace REDasm {

class CHIP8Emulator : public VMIL::Emulator
{
    public:
        CHIP8Emulator(DisassemblerFunctions* disassembler);
        virtual void translate(const InstructionPtr& instruction, VMILInstructionList& vminstructions);
};

} // namespace REDasm

#endif // CHIP8EMULATOR_H
