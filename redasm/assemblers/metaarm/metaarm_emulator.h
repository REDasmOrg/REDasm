#ifndef METAARM_EMULATOR_H
#define METAARM_EMULATOR_H

#include "../../vmil/vmil_emulator.h"

namespace REDasm {

class MetaARMEmulator : public VMIL::Emulator
{
    public:
        MetaARMEmulator(DisassemblerAPI* disassembler);
        virtual bool emulate(const InstructionPtr &instruction);

    private:
        void translateLdr(const InstructionPtr& instruction, VMIL::VMILInstructionPtr& vminstruction, VMIL::VMILInstructionList& vminstructions) const;
        void translateBranch(const InstructionPtr& instruction, VMIL::VMILInstructionPtr& vminstruction, VMIL::VMILInstructionList& vminstructions) const;
};

} // namespace REDasm

#endif // METAARM_EMULATOR_H
