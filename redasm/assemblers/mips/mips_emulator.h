#ifndef MIPS_EMULATOR_H
#define MIPS_EMULATOR_H

#include "../../vmil/vmil_emulator.h"

namespace REDasm {

class MIPSEmulator : public VMIL::Emulator
{
    public:
        MIPSEmulator(DisassemblerAPI* disassembler);
        virtual bool emulate(const InstructionPtr &instruction);

    private:
        void translateLxx(const InstructionPtr& instruction, VMIL::VMILInstructionPtr& vminstruction, VMIL::VMILInstructionList& vminstructions) const;
        void translateSxx(const InstructionPtr& instruction, VMIL::VMILInstructionPtr& vminstruction, VMIL::VMILInstructionList& vminstructions) const;
        void translateLUI(const InstructionPtr& instruction, VMIL::VMILInstructionPtr& vminstruction, VMIL::VMILInstructionList& vminstructions) const;
        void translateNOP(const InstructionPtr& instruction, VMIL::VMILInstructionPtr& vminstruction, VMIL::VMILInstructionList& vminstructions) const;
        void translateSLL(const InstructionPtr& instruction, VMIL::VMILInstructionPtr& vminstruction, VMIL::VMILInstructionList& vminstructions) const;
        void translateSRL(const InstructionPtr& instruction, VMIL::VMILInstructionPtr& vminstruction, VMIL::VMILInstructionList& vminstructions) const;
        void translateMath(const InstructionPtr& instruction, VMIL::VMILInstructionPtr& vminstruction, VMIL::VMILInstructionList& vminstructions) const;
        void translateBitwise(const InstructionPtr& instruction, VMIL::VMILInstructionPtr& vminstruction, VMIL::VMILInstructionList& vminstructions) const;
};

} // namespace REDasm

#endif // MIPS_EMULATOR_H
