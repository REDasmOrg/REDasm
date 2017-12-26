#ifndef MIPS_EMULATOR_H
#define MIPS_EMULATOR_H

#include <capstone.h>
#include "../../vmil/vmil_emulator.h"

namespace REDasm {

class MIPSEmulator : public VMIL::Emulator
{


    public:
        MIPSEmulator(DisassemblerFunctions* disassembler);
        virtual void translate(const InstructionPtr& instruction, VMIL::VMILInstructionList& vminstructions);

    private:

};

} // namespace REDasm

#endif // MIPS_EMULATOR_H
