#include "chip8emulator.h"

namespace REDasm {

CHIP8Emulator::CHIP8Emulator(DisassemblerFunctions *disassembler): VMIL::Emulator(disassembler)
{

}

void CHIP8Emulator::translate(const InstructionPtr &instruction, VMILInstructionList &vminstructions)
{
    u16 op = instruction->id & 0xF000;
    VMIL::VMILInstructionPtr vminstruction;

    if(op == 0x1000)
    {
        vminstruction = this->createInstruction(instruction, VMIL::Opcodes::Jcc);
        vminstruction->imm(VMIL_TRUE);
        vminstruction->imm(instruction->target());
    }
    else if(op == 0x6000)
    {
        vminstruction = this->createInstruction(instruction, VMIL::Opcodes::Str);
        vminstruction->op(instruction->operands[0]);
        vminstruction->op(instruction->operands[1]);
    }
    else if(op == 0x7000)
    {
        vminstruction = this->createInstruction(instruction, VMIL::Opcodes::Add);
        vminstruction->op(instruction->operands[0]);
        vminstruction->imm(instruction->operands[1].u_value);
    }
    else if(op == 0x8000)
    {
        u8 t = instruction->id = 0x000F;

        if(t == 1)
            vminstruction = this->createInstruction(instruction, VMIL::Opcodes::Or);
        else if(t == 2)
            vminstruction = this->createInstruction(instruction, VMIL::Opcodes::And);
        else if(t == 3)
            vminstruction = this->createInstruction(instruction, VMIL::Opcodes::Xor);
        else if(t == 4)
            vminstruction = this->createInstruction(instruction, VMIL::Opcodes::Add);
        else if(t == 5)
            vminstruction = this->createInstruction(instruction, VMIL::Opcodes::Sub);
        else
        {
            vminstruction = this->invalidInstruction(instruction);
            return;
        }

        vminstruction->op(instruction->operands[0]);
        vminstruction->op(instruction->operands[0]);
        vminstruction->op(instruction->operands[1]);
    }
    else
        vminstruction = this->invalidInstruction(instruction);

    vminstructions.push_back(vminstruction);
}

} // namespace REDasm
