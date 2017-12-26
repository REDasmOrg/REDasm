#ifndef VMIL_EMULATOR_H
#define VMIL_EMULATOR_H

#include <unordered_map>
#include "../disassembler/disassemblerfunctions.h"
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
        Emulator(DisassemblerFunctions* disassembler);
        virtual ~Emulator();
        void translate(const InstructionPtr& instruction, VMILInstructionList& vminstructions);
        void emulate(const InstructionPtr &instruction);
        void reset();

    protected:
        virtual instruction_id_t getInstructionId(const InstructionPtr& instruction) const;
        vmilregister_t createMemDisp(const InstructionPtr& instruction, size_t opidx, VMILInstructionList& vminstructions) const;
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

    protected:
        TranslateMap _translatemap;

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
