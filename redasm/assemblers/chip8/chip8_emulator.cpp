#include "chip8_emulator.h"
#include "chip8_registers.h"

namespace REDasm {

CHIP8Emulator::CHIP8Emulator(DisassemblerFunctions *disassembler): VMIL::Emulator(disassembler)
{
    VMIL_TRANSLATE_OPCODE(0x1000, 1xxx);
    VMIL_TRANSLATE_OPCODE(0x3000, 3xxx);
    VMIL_TRANSLATE_OPCODE(0x4000, 4xxx);
    VMIL_TRANSLATE_OPCODE(0x6000, 6xxx);
    VMIL_TRANSLATE_OPCODE(0x7000, 7xxx);
    VMIL_TRANSLATE_OPCODE(0x7000, 8xxx);
    VMIL_TRANSLATE_OPCODE(0x9000, 9xxx);
    VMIL_TRANSLATE_OPCODE(0xA000, Axxx);
    VMIL_TRANSLATE_OPCODE(0xE000, Exxx);
    VMIL_TRANSLATE_OPCODE(0xF000, Fxxx);
}

instruction_id_t CHIP8Emulator::getInstructionId(const InstructionPtr &instruction) const
{
    return instruction->id & 0xF000;
}

void CHIP8Emulator::translate1xxx(const InstructionPtr &instruction, VMIL::VMILInstructionPtr &vminstruction, VMIL::VMILInstructionList& vminstructions)
{
    vminstruction = VMIL::emitJcc(instruction);
    vminstruction->imm(VMIL_TRUE);
    vminstruction->imm(VMIL_ADDRESS(instruction->target()));
    vminstruction->target_idx = 1;
    vminstructions.push_back(vminstruction);
}

void CHIP8Emulator::translate3xxx(const InstructionPtr &instruction, VMIL::VMILInstructionPtr &vminstruction, VMIL::VMILInstructionList &vminstructions)
{
    this->emitEQ(instruction, 0, 1, vminstructions);

    vminstruction = VMIL::emitJcc(instruction, VMIL_INSTRUCTION_I(vminstructions));
    vminstruction->reg(VMIL_DEFAULT_REGISTER);
    vminstruction->imm(VMIL_ADDRESS(instruction->target()));
    vminstruction->target_idx = 1;
    vminstructions.push_back(vminstruction);
}

void CHIP8Emulator::translate4xxx(const InstructionPtr &instruction, VMIL::VMILInstructionPtr &vminstruction, VMIL::VMILInstructionList &vminstructions)
{
    this->emitNEQ(instruction, 0, 1, vminstructions);

    vminstruction = VMIL::emitJcc(instruction, VMIL_INSTRUCTION_I(vminstructions));
    vminstruction->reg(VMIL_DEFAULT_REGISTER);
    vminstruction->imm(VMIL_ADDRESS(instruction->target()));
    vminstruction->target_idx = 1;
    vminstructions.push_back(vminstruction);
}

void CHIP8Emulator::translate5xxx(const InstructionPtr &instruction, VMIL::VMILInstructionPtr &vminstruction, VMIL::VMILInstructionList &vminstructions)
{
    this->translate3xxx(instruction, vminstruction, vminstructions);
}

void CHIP8Emulator::translate6xxx(const InstructionPtr &instruction, VMIL::VMILInstructionPtr &vminstruction, VMIL::VMILInstructionList &vminstructions)
{
    vminstruction = VMIL::emitStr(instruction);
    vminstruction->op(instruction->operands[0]);
    vminstruction->op(instruction->operands[1]);
    vminstructions.push_back(vminstruction);
}

void CHIP8Emulator::translate7xxx(const InstructionPtr &instruction, VMIL::VMILInstructionPtr &vminstruction, VMIL::VMILInstructionList &vminstructions)
{
    vminstruction = VMIL::emitAdd(instruction);
    vminstruction->op(instruction->operands[0]);
    vminstruction->op(instruction->operands[0]);
    vminstruction->imm(instruction->operands[1].u_value);
    vminstructions.push_back(vminstruction);
}

void CHIP8Emulator::translate8xxx(const InstructionPtr &instruction, VMIL::VMILInstructionPtr &vminstruction, VMIL::VMILInstructionList &vminstructions)
{
    u8 t = instruction->id & 0x000F;

    if(t == 0x1)
        vminstruction = VMIL::emitOr(instruction);
    else if(t == 0x2)
        vminstruction = VMIL::emitAnd(instruction);
    else if(t == 0x3)
        vminstruction = VMIL::emitXor(instruction);
    else if(t == 0x4)
        vminstruction = VMIL::emitAdd(instruction);
    else if(t == 0x5)
        vminstruction = VMIL::emitSub(instruction);
    else if(t == 0x6)
        vminstruction = VMIL::emitRsh(instruction);
    else if(t == 0xE)
        vminstruction = VMIL::emitLsh(instruction);
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

void CHIP8Emulator::translate9xxx(const InstructionPtr &instruction, VMIL::VMILInstructionPtr &vminstruction, VMIL::VMILInstructionList &vminstructions)
{
    if((instruction->id & 0x000F) != 0)
        return;

    this->translate4xxx(instruction, vminstruction, vminstructions);
}

void CHIP8Emulator::translateAxxx(const InstructionPtr &instruction, VMIL::VMILInstructionPtr &vminstruction, VMIL::VMILInstructionList &vminstructions)
{
    vminstruction = VMIL::emitStr(instruction);
    vminstruction->op(instruction->op(0));
    vminstruction->op(instruction->op(1));
    vminstructions.push_back(vminstruction);
}

void CHIP8Emulator::translateExxx(const InstructionPtr &instruction, VMIL::VMILInstructionPtr &vminstruction, VMIL::VMILInstructionList &vminstructions)
{
    u16 op = instruction->id & 0xFF;

    if((op != 0x9E) && (op != 0xA1))
        return;

    if(op == 0xA1)
    {
        vminstruction = VMIL::emitBisz(instruction);
        vminstruction->reg(VMIL_REGISTER(0));
        vminstruction->op(instruction->op(0));
        vminstructions.push_back(vminstruction);
    }

    vminstruction = VMIL::emitJcc(instruction, VMIL_INSTRUCTION_I(vminstructions));

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

void CHIP8Emulator::translateFxxx(const InstructionPtr &instruction, VMIL::VMILInstructionPtr &vminstruction, VMIL::VMILInstructionList &vminstructions)
{
    u16 op = instruction->id & 0xFF;

    if(op == 0x33)
        this->translateBCD(instruction, vminstruction, vminstructions);
    else if((op == 0x55) || (op == 0x65))
        this->translatexxRA(instruction, vminstruction, vminstructions);
}

void CHIP8Emulator::translateBCD(const InstructionPtr &instruction, VMIL::VMILInstructionPtr &vminstruction, VMIL::VMILInstructionList &vminstructions)
{
    /*
     * BCD instruction:
     * RAM[I]     = (vr) / 100
     * RAM[I + 1] = (vr / 10) % 10
     * RAM[I + 2] = (vr % 100) % 10
     */

    vminstruction = VMIL::emitStr(instruction);
    vminstruction->reg(VMIL_REGISTER(0)); // i
    vminstruction->reg(CHIP8_REG_I_ID, CHIP8_REG_I);
    vminstruction->cmt("Load i").cmt("*** Begin BCD ***");
    vminstructions.push_back(vminstruction);

    for(size_t i = 0; i < 3; i++)
    {
        if(i)
        {
            vminstruction = VMIL::emitAdd(instruction, VMIL_INSTRUCTION_I(vminstructions));
            vminstruction->reg(VMIL_REGISTER(0));
            vminstruction->reg(VMIL_REGISTER(0));
            vminstruction->imm(1);
            vminstruction->cmt("i++");
            vminstructions.push_back(vminstruction);
        }

        if(i < 2)
        {
            vminstruction = VMIL::emitDiv(instruction, VMIL_INSTRUCTION_I(vminstructions));
            vminstruction->reg(VMIL_REGISTER(2));
            vminstruction->op(instruction->op(0));
            vminstruction->imm((i == 0) ? 100 : 10);
            vminstructions.push_back(vminstruction);
        }
        else
        {
            vminstruction = VMIL::emitMod(instruction, VMIL_INSTRUCTION_I(vminstructions));
            vminstruction->reg(VMIL_REGISTER(2));
            vminstruction->op(instruction->op(0));
            vminstruction->imm(100);
            vminstructions.push_back(vminstruction);
        }

        if(i)
        {
            vminstruction = VMIL::emitMod(instruction, VMIL_INSTRUCTION_I(vminstructions));
            vminstruction->reg(VMIL_REGISTER(2));
            vminstruction->reg(VMIL_REGISTER(2));
            vminstruction->imm(10);
            vminstructions.push_back(vminstruction);
        }

        vminstruction = VMIL::emitStm(instruction, VMIL_INSTRUCTION_I(vminstructions));
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

void CHIP8Emulator::translatexxRA(const InstructionPtr &instruction, VMIL::VMILInstructionPtr &vminstruction, VMIL::VMILInstructionList &vminstructions)
{
    if(!instruction->is(InstructionTypes::Load) && !instruction->is(InstructionTypes::Store))
        return;

    vminstruction = VMIL::emitStr(instruction);
    vminstruction->reg(VMIL_REGISTER(0)); // i
    vminstruction->reg(CHIP8_REG_I_ID, CHIP8_REG_I);

    if(instruction->is(InstructionTypes::Load))
        vminstruction->cmt("*** Begin Load ***");
    else
        vminstruction->cmt("*** Begin Store ***");

    vminstruction->cmt("Load i");
    vminstructions.push_back(vminstruction);

    VMIL::vmilopcode_t opcode = instruction->is(InstructionTypes::Load) ? VMIL::Opcodes::Ldm : VMIL::Opcodes::Stm;
    const Operand& op = instruction->op(0);

    for(register_t r = op.reg.r; r >= 0; r--)
    {
        vminstruction = VMIL::emitInstruction(instruction, opcode, VMIL_INSTRUCTION_I(vminstructions));
        vminstruction->reg(VMIL_REGISTER(0));
        vminstruction->reg(r, op.reg.extra_type);
        vminstructions.push_back(vminstruction);

        if(r)
        {
            vminstruction = VMIL::emitSub(instruction, VMIL_INSTRUCTION_I(vminstructions));
            vminstruction->reg(VMIL_REGISTER(0));
            vminstruction->reg(VMIL_REGISTER(0));
            vminstruction->imm(1);
            vminstruction->cmt("i--");
            vminstructions.push_back(vminstruction);
        }
    }

    if(instruction->is(InstructionTypes::Load))
        vminstruction->cmt("*** End Load ***");
    else
        vminstruction->cmt("*** End Store ***");
}

} // namespace REDasm
