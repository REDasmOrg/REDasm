#include "chip8emulator.h"
#include "chip8registers.h"

#define TRANSLATE_OPCODE(opcode) _translatemap[0x ## opcode * 0x1000] = [this](const InstructionPtr& instruction, VMIL::VMILInstructionPtr& vminstruction, VMILInstructionList& vminstructions) { \
                                                                            translate##opcode##xxx(instruction, vminstruction, vminstructions); \
                                                                        }

namespace REDasm {

CHIP8Emulator::CHIP8Emulator(DisassemblerFunctions *disassembler): VMIL::Emulator(disassembler)
{
    TRANSLATE_OPCODE(1);
    TRANSLATE_OPCODE(3);
    TRANSLATE_OPCODE(4);
    TRANSLATE_OPCODE(6);
    TRANSLATE_OPCODE(7);
    TRANSLATE_OPCODE(8);
    TRANSLATE_OPCODE(9);
    TRANSLATE_OPCODE(A);
    TRANSLATE_OPCODE(E);
    TRANSLATE_OPCODE(F);
}

void CHIP8Emulator::translate(const InstructionPtr &instruction, VMILInstructionList &vminstructions)
{
    u16 op = instruction->id & 0xF000;
    VMIL::VMILInstructionPtr vminstruction;
    auto it = this->_translatemap.find(op);

    if(it != this->_translatemap.end())
        it->second(instruction, vminstruction, vminstructions);

    if(!vminstructions.empty())
        return;

    vminstruction = this->invalidInstruction(instruction);
    vminstructions.push_back(vminstruction);
}

void CHIP8Emulator::translate1xxx(const InstructionPtr &instruction, VMIL::VMILInstructionPtr &vminstruction, VMIL::Emulator::VMILInstructionList& vminstructions)
{
    vminstruction = this->createInstruction(instruction, VMIL::Opcodes::Jcc);
    vminstruction->imm(VMIL_TRUE);
    vminstruction->imm(VMIL_ADDRESS(instruction->target()));
    vminstruction->target_idx = 1;
    vminstructions.push_back(vminstruction);
}

void CHIP8Emulator::translate3xxx(const InstructionPtr &instruction, VMIL::VMILInstructionPtr &vminstruction, VMIL::Emulator::VMILInstructionList &vminstructions)
{
    vminstruction = this->createEQ(instruction, 0, 1, vminstructions, VMIL::Opcodes::Jcc, [this, instruction](VMIL::VMILInstructionPtr& vminstruction, VMIL::vmilregister_t reg) {
        vminstruction->reg(VMIL_REGISTER(reg));
        vminstruction->imm(VMIL_ADDRESS(instruction->target()));
        vminstruction->target_idx = 1;
    });

    vminstructions.push_back(vminstruction);
}

void CHIP8Emulator::translate4xxx(const InstructionPtr &instruction, VMIL::VMILInstructionPtr &vminstruction, VMIL::Emulator::VMILInstructionList &vminstructions)
{
    vminstruction = this->createNEQ(instruction, 0, 1, vminstructions, VMIL::Opcodes::Jcc, [this, instruction](VMIL::VMILInstructionPtr& vminstruction, VMIL::vmilregister_t reg) {
        vminstruction->reg(VMIL_REGISTER(reg));
        vminstruction->imm(VMIL_ADDRESS(instruction->target()));
        vminstruction->target_idx = 1;
    });

    vminstructions.push_back(vminstruction);
}

void CHIP8Emulator::translate5xxx(const InstructionPtr &instruction, VMIL::VMILInstructionPtr &vminstruction, VMIL::Emulator::VMILInstructionList &vminstructions)
{
    this->translate3xxx(instruction, vminstruction, vminstructions);
}

void CHIP8Emulator::translate6xxx(const InstructionPtr &instruction, VMIL::VMILInstructionPtr &vminstruction, VMIL::Emulator::VMILInstructionList &vminstructions)
{
    vminstruction = this->createInstruction(instruction, VMIL::Opcodes::Str);
    vminstruction->op(instruction->operands[0]);
    vminstruction->op(instruction->operands[1]);
    vminstructions.push_back(vminstruction);
}

void CHIP8Emulator::translate7xxx(const InstructionPtr &instruction, VMIL::VMILInstructionPtr &vminstruction, VMIL::Emulator::VMILInstructionList &vminstructions)
{
    vminstruction = this->createInstruction(instruction, VMIL::Opcodes::Add);
    vminstruction->op(instruction->operands[0]);
    vminstruction->op(instruction->operands[0]);
    vminstruction->imm(instruction->operands[1].u_value);
    vminstructions.push_back(vminstruction);
}

void CHIP8Emulator::translate8xxx(const InstructionPtr &instruction, VMIL::VMILInstructionPtr &vminstruction, VMIL::Emulator::VMILInstructionList &vminstructions)
{
    u8 t = instruction->id & 0x000F;

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
        return;

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

    vminstructions.push_back(vminstruction);
}

void CHIP8Emulator::translate9xxx(const InstructionPtr &instruction, VMIL::VMILInstructionPtr &vminstruction, VMIL::Emulator::VMILInstructionList &vminstructions)
{
    if((instruction->id & 0x000F) != 0)
        return;

    this->translate4xxx(instruction, vminstruction, vminstructions);
}

void CHIP8Emulator::translateAxxx(const InstructionPtr &instruction, VMIL::VMILInstructionPtr &vminstruction, VMIL::Emulator::VMILInstructionList &vminstructions)
{
    vminstruction = this->createInstruction(instruction, VMIL::Opcodes::Str);
    vminstruction->op(instruction->op(0));
    vminstruction->op(instruction->op(1));
    vminstructions.push_back(vminstruction);
}

void CHIP8Emulator::translateExxx(const InstructionPtr &instruction, VMIL::VMILInstructionPtr &vminstruction, VMIL::Emulator::VMILInstructionList &vminstructions)
{
    u16 op = instruction->id & 0xFF;

    if((op != 0x9E) && (op != 0xA1))
        return;

    if(op == 0xA1)
    {
        vminstruction = this->createInstruction(instruction, VMIL::Opcodes::Bisz);
        vminstruction->reg(VMIL_REGISTER(0));
        vminstruction->op(instruction->op(0));
        vminstructions.push_back(vminstruction);
    }

    vminstruction = this->createInstruction(instruction, VMIL::Opcodes::Jcc, VMIL_INSTRUCTION_I(vminstructions));

    if(op == 0xA1)
    {
        vminstruction->reg(VMIL_REGISTER(0));
        vminstruction->cmt("Jump if key IS NOT PRESSED");
    }
    else
    {
        vminstruction->op(instruction->op(0));
        vminstruction->cmt("Jump if key IS PRESSED");
    }

    vminstruction->imm(VMIL_ADDRESS(instruction->target()));
    vminstruction->target_idx = 0;
    vminstructions.push_back(vminstruction);
}

void CHIP8Emulator::translateFxxx(const InstructionPtr &instruction, VMIL::VMILInstructionPtr &vminstruction, VMIL::Emulator::VMILInstructionList &vminstructions)
{
    u16 op = instruction->id & 0xFF;

    if(op == 0x33)
        this->translateBCD(instruction, vminstruction, vminstructions);
}

void CHIP8Emulator::translateBCD(const InstructionPtr &instruction, VMIL::VMILInstructionPtr &vminstruction, VMIL::Emulator::VMILInstructionList &vminstructions)
{
    /*
     * BCD instruction:
     * RAM[I]     = (vr) / 100
     * RAM[I + 1] = (vr / 10) % 10
     * RAM[I + 2] = (vr % 100) % 10
     */

    vminstruction = this->createInstruction(instruction, VMIL::Opcodes::Str);
    vminstruction->reg(VMIL_REGISTER(0)); // i
    vminstruction->reg(CHIP8_REG_I_ID, CHIP8_REG_I);
    vminstruction->cmt("Load i").cmt("*** Begin BCD ***");
    vminstructions.push_back(vminstruction);

    for(size_t i = 0; i < 3; i++)
    {
        if(i)
        {
            vminstruction = this->createInstruction(instruction, VMIL::Opcodes::Add, VMIL_INSTRUCTION_I(vminstructions));
            vminstruction->reg(VMIL_REGISTER(0));
            vminstruction->reg(VMIL_REGISTER(0));
            vminstruction->imm(1);
            vminstruction->cmt("i++");
            vminstructions.push_back(vminstruction);
        }

        if(i < 2)
        {
            vminstruction = this->createInstruction(instruction, VMIL::Opcodes::Div, VMIL_INSTRUCTION_I(vminstructions));
            vminstruction->reg(VMIL_REGISTER(2));
            vminstruction->op(instruction->op(0));
            vminstruction->imm((i == 0) ? 100 : 10);
            vminstructions.push_back(vminstruction);
        }
        else
        {
            vminstruction = this->createInstruction(instruction, VMIL::Opcodes::Mod, VMIL_INSTRUCTION_I(vminstructions));
            vminstruction->reg(VMIL_REGISTER(2));
            vminstruction->op(instruction->op(0));
            vminstruction->imm(100);
            vminstructions.push_back(vminstruction);
        }

        if(i)
        {
            vminstruction = this->createInstruction(instruction, VMIL::Opcodes::Mod, VMIL_INSTRUCTION_I(vminstructions));
            vminstruction->reg(VMIL_REGISTER(2));
            vminstruction->reg(VMIL_REGISTER(2));
            vminstruction->imm(10);
            vminstructions.push_back(vminstruction);
        }

        vminstruction = this->createInstruction(instruction, VMIL::Opcodes::Stm, VMIL_INSTRUCTION_I(vminstructions));
        vminstruction->reg(VMIL_REGISTER(0));
        vminstruction->reg(VMIL_REGISTER(2));

        if(i)
            vminstruction->cmt("Write RAM[i + " + std::to_string(i) + "]");
        else
            vminstruction->cmt("Write RAM[i]");

        vminstructions.push_back(vminstruction);
    }

    vminstruction->cmt("*** End BCD ***");
}

} // namespace REDasm
