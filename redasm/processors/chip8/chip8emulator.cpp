#include "chip8emulator.h"

#define TRANSLATE_OPCODE(opcode) _translatemap[0x ## opcode * 0x1000] = [this](const InstructionPtr& instruction, VMIL::VMILInstructionPtr& vminstruction, VMILInstructionList& vminstructions) { \
                                                                            translate##opcode##xxx(instruction, vminstruction, vminstructions); \
                                                                        }

namespace REDasm {

CHIP8Emulator::CHIP8Emulator(DisassemblerFunctions *disassembler): VMIL::Emulator(disassembler)
{
    TRANSLATE_OPCODE(1);
    TRANSLATE_OPCODE(3);
    TRANSLATE_OPCODE(6);
    TRANSLATE_OPCODE(7);
    TRANSLATE_OPCODE(8);
    TRANSLATE_OPCODE(A);
}

void CHIP8Emulator::translate(const InstructionPtr &instruction, VMILInstructionList &vminstructions)
{
    u16 op = instruction->id & 0xF000;
    VMIL::VMILInstructionPtr vminstruction;
    auto it = this->_translatemap.find(op);

    if(it != this->_translatemap.end())
        it->second(instruction, vminstruction, vminstructions);

    if(!vminstruction)
        vminstruction = this->invalidInstruction(instruction);

    vminstructions.push_back(vminstruction);
}

void CHIP8Emulator::translate1xxx(const InstructionPtr &instruction, VMIL::VMILInstructionPtr &vminstruction, VMIL::Emulator::VMILInstructionList &)
{
    vminstruction = this->createInstruction(instruction, VMIL::Opcodes::Jcc);
    vminstruction->imm(VMIL_TRUE);
    vminstruction->imm(VMIL_ADDRESS(instruction->target()));
    vminstruction->target_idx = 1;
}

void CHIP8Emulator::translate3xxx(const InstructionPtr &instruction, VMIL::VMILInstructionPtr &vminstruction, VMIL::Emulator::VMILInstructionList &vminstructions)
{
    vminstruction = this->createIfEqual(instruction, 0, 1, vminstructions, VMIL::Opcodes::Jcc, [this, instruction](VMIL::VMILInstructionPtr& vminstruction, VMIL::vmilregister_t reg) {
        vminstruction->reg(VMIL_REGISTER(reg));
        vminstruction->imm(VMIL_ADDRESS(instruction->target()));
        vminstruction->target_idx = 1;
    });
}

void CHIP8Emulator::translate6xxx(const InstructionPtr &instruction, VMIL::VMILInstructionPtr &vminstruction, VMIL::Emulator::VMILInstructionList &)
{
    vminstruction = this->createInstruction(instruction, VMIL::Opcodes::Str);
    vminstruction->op(instruction->operands[0]);
    vminstruction->op(instruction->operands[1]);
}

void CHIP8Emulator::translate7xxx(const InstructionPtr &instruction, VMIL::VMILInstructionPtr &vminstruction, VMIL::Emulator::VMILInstructionList &)
{
    vminstruction = this->createInstruction(instruction, VMIL::Opcodes::Add);
    vminstruction->op(instruction->operands[0]);
    vminstruction->imm(instruction->operands[1].u_value);
}

void CHIP8Emulator::translate8xxx(const InstructionPtr &instruction, VMIL::VMILInstructionPtr &vminstruction, VMIL::Emulator::VMILInstructionList &)
{
    u8 t = instruction->id = 0x000F;

    if(t == 0x1)
        vminstruction = this->createInstruction(instruction, VMIL::Opcodes::Or);
    else if(t == 0x2)
        vminstruction = this->createInstruction(instruction, VMIL::Opcodes::And);
    else if(t == 0x3)
        vminstruction = this->createInstruction(instruction, VMIL::Opcodes::Xor);
    else if(t == 0x4)
        vminstruction = this->createInstruction(instruction, VMIL::Opcodes::Add);
    else if(t == 0x5)
        vminstruction = this->createInstruction(instruction, VMIL::Opcodes::Sub);
    else if(t == 0x6)
        vminstruction = this->createInstruction(instruction, VMIL::Opcodes::Rsh);
    else if(t == 0xE)
        vminstruction = this->createInstruction(instruction, VMIL::Opcodes::Lsh);
    else
    {
        vminstruction = this->invalidInstruction(instruction);
        return;
    }

    if((t == 0x6) || (t == 0xE))
    {
        vminstruction->op(instruction->operands[0]);
        vminstruction->imm(1);
    }
    else
    {
        vminstruction->op(instruction->operands[0]);
        vminstruction->op(instruction->operands[0]);
        vminstruction->op(instruction->operands[1]);
    }
}

void CHIP8Emulator::translateAxxx(const InstructionPtr &instruction, VMIL::VMILInstructionPtr &vminstruction, VMIL::Emulator::VMILInstructionList &)
{
    vminstruction = this->createInstruction(instruction, VMIL::Opcodes::Str);
    vminstruction->op(instruction->op(0));
    vminstruction->op(instruction->op(1));
}

} // namespace REDasm
