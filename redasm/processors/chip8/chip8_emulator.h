#ifndef CHIP8_EMULATOR_H
#define CHIP8_EMULATOR_H

#include <unordered_map>
#include "../../vmil/vmil_emulator.h"

namespace REDasm {

class CHIP8Emulator : public VMIL::Emulator
{
    private:
        typedef std::function<void(const InstructionPtr&, VMIL::VMILInstructionPtr&, VMILInstructionList& vminstructions)> TranslateCallback;
        typedef std::unordered_map<u16, TranslateCallback> TranslateMap;

    public:
        CHIP8Emulator(DisassemblerFunctions* disassembler);
        virtual void translate(const InstructionPtr& instruction, VMILInstructionList& vminstructions);

    private:
        void translate1xxx(const InstructionPtr& instruction, VMIL::VMILInstructionPtr& vminstruction, VMILInstructionList& vminstructions);
        void translate3xxx(const InstructionPtr& instruction, VMIL::VMILInstructionPtr& vminstruction, VMILInstructionList& vminstructions);
        void translate4xxx(const InstructionPtr& instruction, VMIL::VMILInstructionPtr& vminstruction, VMILInstructionList& vminstructions);
        void translate5xxx(const InstructionPtr& instruction, VMIL::VMILInstructionPtr& vminstruction, VMILInstructionList& vminstructions);
        void translate6xxx(const InstructionPtr& instruction, VMIL::VMILInstructionPtr& vminstruction, VMILInstructionList& vminstructions);
        void translate7xxx(const InstructionPtr& instruction, VMIL::VMILInstructionPtr& vminstruction, VMILInstructionList& vminstructions);
        void translate8xxx(const InstructionPtr& instruction, VMIL::VMILInstructionPtr& vminstruction, VMILInstructionList& vminstructions);
        void translate9xxx(const InstructionPtr& instruction, VMIL::VMILInstructionPtr& vminstruction, VMILInstructionList& vminstructions);
        void translateAxxx(const InstructionPtr& instruction, VMIL::VMILInstructionPtr& vminstruction, VMILInstructionList& vminstructions);
        void translateExxx(const InstructionPtr& instruction, VMIL::VMILInstructionPtr& vminstruction, VMILInstructionList& vminstructions);
        void translateFxxx(const InstructionPtr& instruction, VMIL::VMILInstructionPtr& vminstruction, VMILInstructionList& vminstructions);

    private:
        void translateBCD(const InstructionPtr& instruction, VMIL::VMILInstructionPtr& vminstruction, VMILInstructionList& vminstructions);
        void translatexxRA(const InstructionPtr& instruction, VMIL::VMILInstructionPtr& vminstruction, VMILInstructionList& vminstructions);

    private:
        TranslateMap _translatemap;
};

} // namespace REDasm

#endif // CHIP8_EMULATOR_H
