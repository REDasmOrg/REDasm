#ifndef CHIP8EMULATOR_H
#define CHIP8EMULATOR_H

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
        void translate1xxx(const InstructionPtr& instruction, VMIL::VMILInstructionPtr& vminstruction, VMILInstructionList&);
        void translate3xxx(const InstructionPtr& instruction, VMIL::VMILInstructionPtr& vminstruction, VMILInstructionList& vminstructions);
        void translate6xxx(const InstructionPtr& instruction, VMIL::VMILInstructionPtr& vminstruction, VMILInstructionList&);
        void translate7xxx(const InstructionPtr& instruction, VMIL::VMILInstructionPtr& vminstruction, VMILInstructionList&);
        void translate8xxx(const InstructionPtr& instruction, VMIL::VMILInstructionPtr& vminstruction, VMILInstructionList&);
        void translateAxxx(const InstructionPtr& instruction, VMIL::VMILInstructionPtr& vminstruction, VMILInstructionList&);

    private:
        TranslateMap _translatemap;
};

} // namespace REDasm

#endif // CHIP8EMULATOR_H
