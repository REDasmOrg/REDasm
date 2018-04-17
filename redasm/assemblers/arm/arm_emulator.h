#ifndef ARM_EMULATOR_H
#define ARM_EMULATOR_H

#include "../../vmil/vmil_emulator.h"

namespace REDasm {

class ARMEmulator : public VMIL::Emulator
{
    public:
        ARMEmulator(DisassemblerAPI* disassembler);

    private:
        void translateLdr(const InstructionPtr& instruction, VMIL::VMILInstructionPtr& vminstruction, VMIL::VMILInstructionList& vminstructions) const;
        void translateBranch(const InstructionPtr& instruction, VMIL::VMILInstructionPtr& vminstruction, VMIL::VMILInstructionList& vminstructions) const;
};

} // namespace REDasm

#endif // ARM_EMULATOR_H
