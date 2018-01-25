#ifndef CHIP8_EMULATOR_H
#define CHIP8_EMULATOR_H

#include "../../vmil/vmil_emulator.h"

namespace REDasm {

class CHIP8Emulator : public VMIL::Emulator
{
    public:
        CHIP8Emulator(DisassemblerAPI* disassembler);

    protected:
        virtual instruction_id_t getInstructionId(const InstructionPtr &instruction) const;

    private:
        void translate1xxx(const InstructionPtr& instruction, VMIL::VMILInstructionPtr& vminstruction, VMIL::VMILInstructionList& vminstructions);
        void translate3xxx(const InstructionPtr& instruction, VMIL::VMILInstructionPtr& vminstruction, VMIL::VMILInstructionList& vminstructions);
        void translate4xxx(const InstructionPtr& instruction, VMIL::VMILInstructionPtr& vminstruction, VMIL::VMILInstructionList& vminstructions);
        void translate5xxx(const InstructionPtr& instruction, VMIL::VMILInstructionPtr& vminstruction, VMIL::VMILInstructionList& vminstructions);
        void translate6xxx(const InstructionPtr& instruction, VMIL::VMILInstructionPtr& vminstruction, VMIL::VMILInstructionList& vminstructions);
        void translate7xxx(const InstructionPtr& instruction, VMIL::VMILInstructionPtr& vminstruction, VMIL::VMILInstructionList& vminstructions);
        void translate8xxx(const InstructionPtr& instruction, VMIL::VMILInstructionPtr& vminstruction, VMIL::VMILInstructionList& vminstructions);
        void translate9xxx(const InstructionPtr& instruction, VMIL::VMILInstructionPtr& vminstruction, VMIL::VMILInstructionList& vminstructions);
        void translateAxxx(const InstructionPtr& instruction, VMIL::VMILInstructionPtr& vminstruction, VMIL::VMILInstructionList& vminstructions);
        void translateExxx(const InstructionPtr& instruction, VMIL::VMILInstructionPtr& vminstruction, VMIL::VMILInstructionList& vminstructions);
        void translateFxxx(const InstructionPtr& instruction, VMIL::VMILInstructionPtr& vminstruction, VMIL::VMILInstructionList& vminstructions);

    private:
        void translateBCD(const InstructionPtr& instruction, VMIL::VMILInstructionPtr& vminstruction, VMIL::VMILInstructionList& vminstructions);
        void translatexxRA(const InstructionPtr& instruction, VMIL::VMILInstructionPtr& vminstruction, VMIL::VMILInstructionList& vminstructions);
};

} // namespace REDasm

#endif // CHIP8_EMULATOR_H
