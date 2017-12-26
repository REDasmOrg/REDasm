#ifndef VMIL_EMULATOR_H
#define VMIL_EMULATOR_H

#include "../redasm.h"
#include "../disassembler/disassemblerfunctions.h"
#include "vmil_instructions.h"

namespace REDasm {
namespace VMIL {

class Emulator
{
    private:
        typedef std::function<void(const InstructionPtr&)> OpCallback;
        typedef std::function<void(VMILInstructionPtr&, vmilregister_t)> CondCallback;
        typedef std::unordered_map<u32, OpCallback> OpMap;
        typedef std::unordered_map<register_t, u64> Registers;
        typedef std::unordered_map<address_t, u64> Memory;

    public:
        typedef std::vector<VMILInstructionPtr> VMILInstructionList;

    public:
        Emulator(DisassemblerFunctions* disassembler);
        virtual ~Emulator();
        virtual void translate(const InstructionPtr& instruction, VMILInstructionList& vminstructions) = 0;
        void emulate(const InstructionPtr &instruction);
        void reset();

    protected:
        VMILInstructionPtr createEQ(const InstructionPtr &instruction, size_t opidx1, size_t opidx2, VMILInstructionList& vminstructions, u32 cbvmilopcode, CondCallback cb) const;
        VMILInstructionPtr createNEQ(const InstructionPtr &instruction, size_t opidx1, size_t opidx2, VMILInstructionList& vminstructions, u32 cbvmilopcode, CondCallback cb) const;
        VMILInstructionPtr createInstruction(const InstructionPtr &instruction, u32 vmilopcode, u32 index = 0) const;
        VMILInstructionPtr invalidInstruction(const InstructionPtr &instruction) const;

    private:
        void write(const Operand& operand, u64 value);
        u64 read(const Operand& operand);
        void writeT(register_t reg, u64 value);
        void write(register_t reg, u64 value);
        u64 readT(register_t reg);
        u64 read(register_t reg);
        void writeMemory(address_t address, u64 value);
        u64 readMemory(address_t address);
        void writeRegister(Registers& registers, register_t reg, u64 value);
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

    private:
        DisassemblerFunctions* _disassembler;
        OpMap _opmap;
        Registers _tempregisters;
        Registers _registers;
        Memory _memory;
};

} // namespace VMIL
} // namespace REDasm

#endif // VMIL_EMULATOR_H
