#ifndef VMIL_EMULATOR_H
#define VMIL_EMULATOR_H

#include <unordered_map>
#include "../disassembler/disassemblerapi.h"
#include "../redasm.h"
#include "vmil_instructions.h"

#define VMIL_TRANSLATE_CALLBACK(id) [this](const InstructionPtr& instruction, VMIL::VMILInstructionPtr& vminstruction, VMIL::VMILInstructionList& vminstructions) { \
                                            translate##id(instruction, vminstruction, vminstructions); \
                                        }

#define VMIL_TRANSLATE_OPCODE(key, id) _translatemap[key] = VMIL_TRANSLATE_CALLBACK(id)

namespace REDasm {
namespace VMIL {

class Emulator
{
    private:
        typedef std::function<void(const InstructionPtr&)> OpCallback;
        typedef std::function<void(VMILInstructionPtr&, vmilregister_t)> CondCallback;
        typedef std::unordered_map<instruction_id_t, OpCallback> OpMap;
        typedef std::unordered_map<register_t, u64> Registers;
        typedef std::unordered_map<address_t, u64> Memory;

    protected:
        typedef std::function<void(const InstructionPtr&, VMIL::VMILInstructionPtr&, VMILInstructionList& vminstructions)> TranslateCallback;
        typedef std::unordered_map<instruction_id_t, TranslateCallback> TranslateMap;

    public:
        Emulator(DisassemblerAPI* disassembler);
        virtual ~Emulator();
        void setDefaultRegister(vmilregister_t reg);
        vmilregister_t defaultRegister() const;
        bool read(const Operand &operand, u64& value);
        bool translate(const InstructionPtr& instruction, VMILInstructionList& vminstructions);
        virtual bool emulate(const InstructionPtr &instruction);
        virtual void reset();

    protected:
        virtual instruction_id_t getInstructionId(const InstructionPtr& instruction) const;
        void emitDisplacement(const InstructionPtr& instruction, u32 opidx, VMILInstructionList& vminstructions) const;
        void emitEQ(const InstructionPtr &instruction, u32 opidx1, u32 opidx2, VMILInstructionList& vminstructions) const;
        void emitNEQ(const InstructionPtr &instruction, u32 opidx1, u32 opidx2, VMILInstructionList& vminstructions) const;
        void emitLT(const InstructionPtr &instruction, u32 opidx1, u32 opidx2, VMILInstructionList& vminstructions) const;
        void emitGT(const InstructionPtr &instruction, u32 opidx1, u32 opidx2, VMILInstructionList& vminstructions) const;
        void invalidateRegister(register_t reg);
        void write(register_t reg, u64 value);

    private:
        bool canExecute(const VMILInstructionPtr& instruction);
        bool isRegisterValid(const RegisterOperand &regop);
        bool isWriteDestination(const VMILInstructionPtr &instruction, const Operand& operand) const;
        void invalidateRegister(const RegisterOperand& regop);
        void invalidateRegisters(const VMILInstructionPtr &instruction);
        void write(const Operand& operand, u64 value);
        void writeT(vmilregister_t reg, u64 value);
        void writeMemory(address_t address, u64 value);
        void writeRegister(Registers& registers, register_t reg, u64 value);
        u64 read(const Operand& operand);
        u64 read(register_t reg);
        u64 readT(register_t reg);
        u64 readMemory(address_t address, u64 size, bool *ok);
        u64 readRegister(Registers& registers, register_t reg);

    private:
        void emulateAdd(const VMILInstructionPtr& instruction);
        void emulateSub(const VMILInstructionPtr& instruction);
        void emulateMul(const VMILInstructionPtr& instruction);
        void emulateDiv(const VMILInstructionPtr& instruction);
        void emulateMod(const VMILInstructionPtr& instruction);
        void emulateLsh(const VMILInstructionPtr& instruction);
        void emulateRsh(const VMILInstructionPtr& instruction);
        void emulateAnd(const VMILInstructionPtr& instruction);
        void emulateOr(const VMILInstructionPtr& instruction);
        void emulateXor(const VMILInstructionPtr& instruction);
        void emulateStr(const VMILInstructionPtr& instruction);
        void emulateLdm(const VMILInstructionPtr& instruction);
        void emulateStm(const VMILInstructionPtr& instruction);
        void emulateBisz(const VMILInstructionPtr& instruction);
        void emulateJcc(const VMILInstructionPtr& instruction);
        void emulateUndef(const VMILInstructionPtr& instruction);

    protected:
        TranslateMap _translatemap;

    private:
        vmilregister_t _defregister;
        DisassemblerAPI* _disassembler;
        OpMap _opmap;
        Registers _tempregisters;
        Registers _registers;
        Memory _memory;
};

} // namespace VMIL
} // namespace REDasm

#endif // VMIL_EMULATOR_H
