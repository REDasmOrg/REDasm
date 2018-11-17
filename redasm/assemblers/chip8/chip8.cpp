#include "chip8.h"
#include "chip8_printer.h"

#define SET_DECODE_TO(opmask, cb) m_opcodemap[opmask] = [this](u16 opcode, const InstructionPtr& instruction) -> bool { return cb(opcode, instruction); };

namespace REDasm {

CHIP8Assembler::CHIP8Assembler(): AssemblerPlugin()
{
    this->setEndianness(Endianness::BigEndian);

    SET_DECODE_TO(0x0000, decode0xxx);
    SET_DECODE_TO(0x1000, decode1xxx);
    SET_DECODE_TO(0x2000, decode2xxx);
    SET_DECODE_TO(0x3000, decode3xxx);
    SET_DECODE_TO(0x4000, decode4xxx);
    SET_DECODE_TO(0x5000, decode5xxx);
    SET_DECODE_TO(0x6000, decode6xxx);
    SET_DECODE_TO(0x7000, decode7xxx);
    SET_DECODE_TO(0x8000, decode8xxx);
    SET_DECODE_TO(0x9000, decode9xxx);
    SET_DECODE_TO(0xA000, decodeAxxx);
    SET_DECODE_TO(0xB000, decodeBxxx);
    SET_DECODE_TO(0xC000, decodeCxxx);
    SET_DECODE_TO(0xD000, decodeDxxx);
    SET_DECODE_TO(0xE000, decodeExxx);
    SET_DECODE_TO(0xF000, decodeFxxx);
}

const char *CHIP8Assembler::name() const { return "CHIP-8"; }
Printer *CHIP8Assembler::createPrinter(DisassemblerAPI *disassembler) const { return new CHIP8Printer(disassembler); }

bool CHIP8Assembler::decodeInstruction(BufferRef& buffer, const InstructionPtr &instruction)
{
    u16 opcode = buffer;
    instruction->id = opcode;
    instruction->size = sizeof(u16);

    auto it = m_opcodemap.find(opcode & 0xF000);

    if((it == m_opcodemap.end()) || !it->second(opcode, instruction))
        return false;

    return true;
}

void CHIP8Assembler::onDecoded(const InstructionPtr &instruction) const
{
    if(instruction->mnemonic == "rts")
        instruction->type = InstructionTypes::Stop;
    else if(instruction->mnemonic == "jmp")
        instruction->type = InstructionTypes::Jump;
    else if((instruction->mnemonic == "ske") || (instruction->mnemonic == "skne") || (instruction->mnemonic == "skp") || (instruction->mnemonic == "sknp"))
        instruction->type = InstructionTypes::ConditionalJump;
    else if(instruction->mnemonic == "call")
        instruction->type = InstructionTypes::Call;
    else if(instruction->mnemonic == "add")
        instruction->type = InstructionTypes::Add;
    else if(instruction->mnemonic == "sub")
        instruction->type = InstructionTypes::Sub;
    else if(instruction->mnemonic == "and")
        instruction->type = InstructionTypes::And;
    else if(instruction->mnemonic == "or")
        instruction->type = InstructionTypes::Or;
    else if(instruction->mnemonic == "xor")
        instruction->type = InstructionTypes::Xor;
    else if((instruction->mnemonic == "mov") || (instruction->mnemonic == "ldra"))
        instruction->type = InstructionTypes::Load;
    else if(instruction->mnemonic == "stra")
        instruction->type = InstructionTypes::Store;
    else if(instruction->mnemonic == "sys")
        instruction->type = InstructionTypes::Privileged;
}

bool CHIP8Assembler::decode0xxx(u16 opcode, const InstructionPtr &instruction) const
{
    if(opcode == 0x00E0)
        instruction->mnemonic = "cls";
    else if(opcode == 0x00EE)
        instruction->mnemonic = "rts";
    else if(opcode == 0x00FB) // SuperChip only
        instruction->mnemonic = "scright";
    else if(opcode == 0x00FC) // SuperChip only
        instruction->mnemonic = "scleft";
    else if(opcode == 0x00FE) // SuperChip only
        instruction->mnemonic = "low";
    else if(opcode == 0x00FF) // SuperChip only
        instruction->mnemonic = "high";
    else if((opcode & 0x00F0) == 0x00C0) // SuperChip only
    {
        instruction->mnemonic = "scdown";
        instruction->imm(opcode & 0x000F);
    }
    else
    {
        instruction->mnemonic = "sys";
        instruction->imm(opcode & 0x0FFF);
    }

    return true;
}

bool CHIP8Assembler::decode1xxx(u16 opcode, const InstructionPtr &instruction) const
{
    instruction->mnemonic = "jmp";
    instruction->imm(opcode & 0x0FFF);
    instruction->targetOp(0);
    return true;
}

bool CHIP8Assembler::decode2xxx(u16 opcode, const InstructionPtr &instruction) const
{
    instruction->mnemonic = "call";
    instruction->imm(opcode & 0x0FFF);
    instruction->targetOp(0);
    return true;
}

bool CHIP8Assembler::decode3xxx(u16 opcode, const InstructionPtr &instruction) const
{
    instruction->mnemonic = "ske";
    instruction->reg((opcode & 0x0F00) >> 8);
    instruction->imm(opcode & 0x00FF);
    instruction->target(instruction->endAddress() + instruction->size);
    return true;
}

bool CHIP8Assembler::decode4xxx(u16 opcode, const InstructionPtr &instruction) const
{
    instruction->mnemonic = "skne";
    instruction->reg((opcode & 0x0F00) >> 8);
    instruction->imm(opcode & 0x00FF);
    instruction->target(instruction->endAddress() + instruction->size);
    return true;
}

bool CHIP8Assembler::decode5xxx(u16 opcode, const InstructionPtr &instruction) const
{
    if((opcode & 0x000F) != 0)
        return false;

    instruction->mnemonic = "ske";
    instruction->reg((opcode & 0x0F00) >> 8);
    instruction->reg((opcode & 0x00F0) >> 4);
    instruction->target(instruction->endAddress() + instruction->size);
    return true;
}

bool CHIP8Assembler::decode6xxx(u16 opcode, const InstructionPtr &instruction) const
{
    instruction->mnemonic = "mov";
    instruction->reg((opcode & 0x0F00) >> 8);
    instruction->imm(opcode & 0x00FF);
    return true;
}

bool CHIP8Assembler::decode7xxx(u16 opcode, const InstructionPtr &instruction) const
{
    instruction->mnemonic = "add";
    instruction->reg((opcode & 0x0F00) >> 8);
    instruction->imm(opcode & 0x00FF);
    return true;
}

bool CHIP8Assembler::decode8xxx(u16 opcode, const InstructionPtr &instruction) const
{
    u8 op = opcode & 0x000F;

    if(op == 0x0)
        instruction->mnemonic = "mov";
    else if(op == 0x1)
        instruction->mnemonic = "or";
    else if(op == 0x2)
        instruction->mnemonic = "and";
    else if(op == 0x3)
        instruction->mnemonic = "xor";
    else if(op == 0x4)
        instruction->mnemonic = "add";
    else if(op == 0x5)
        instruction->mnemonic = "sub";
    else if(op == 0x6)
        instruction->mnemonic = "shr";
    else if(op == 0x7)
        instruction->mnemonic = "sub";
    else if(op == 0xE)
        instruction->mnemonic = "shl";
    else
        return false;

    instruction->reg((opcode & 0x0F00) >> 8);

    if((op != 0x6) && (op != 0xE)) // Skip 2nd operand if op == shift_instructions
        instruction->reg((opcode & 0x00F0) >> 4);

    return true;
}

bool CHIP8Assembler::decode9xxx(u16 opcode, const InstructionPtr &instruction) const
{
    if((opcode & 0x000F) != 0)
        return false;

    instruction->mnemonic = "skne";
    instruction->reg((opcode & 0x0F00) >> 8);
    instruction->reg((opcode & 0x00F0) >> 4);
    instruction->target(instruction->endAddress() + instruction->size);
    return true;
}

bool CHIP8Assembler::decodeAxxx(u16 opcode, const InstructionPtr &instruction) const
{
    instruction->mnemonic = "mov";
    instruction->reg(CHIP8_REG_I_ID, CHIP8_REG_I);
    instruction->imm(opcode & 0x0FFF);
    return true;
}

bool CHIP8Assembler::decodeBxxx(u16 opcode, const InstructionPtr &instruction) const
{
    instruction->mnemonic = "jmp";
    instruction->disp(CHIP8_REG_V0_ID, opcode & 0x0FFF);
    return true;
}

bool CHIP8Assembler::decodeCxxx(u16 opcode, const InstructionPtr &instruction) const
{
    instruction->mnemonic = "rand";
    instruction->reg((opcode & 0x0F00) >> 8);
    instruction->imm(opcode & 0x00FF);
    return true;
}

bool CHIP8Assembler::decodeDxxx(u16 opcode, const InstructionPtr &instruction) const
{
    instruction->mnemonic = "draw";
    instruction->reg((opcode & 0x0F00) >> 8);
    instruction->reg((opcode & 0x00F0) >> 4);
    instruction->imm(opcode & 0x000F);
    return true;
}

bool CHIP8Assembler::decodeExxx(u16 opcode, const InstructionPtr &instruction) const
{
    u16 op = opcode & 0xFF;

    if(op == 0x9E)
        instruction->mnemonic = "skp";
    else if(op == 0xA1)
        instruction->mnemonic = "sknp";

    instruction->reg((opcode & 0x0F00) >> 8, CHIP8_REG_K);
    instruction->target(instruction->endAddress() + instruction->size);
    return true;
}

bool CHIP8Assembler::decodeFxxx(u16 opcode, const InstructionPtr &instruction) const
{
    u16 op = opcode & 0x00FF;

    if(op == 0x07)
        instruction->mnemonic = "gdelay";
    else if(op == 0x0A)
        instruction->mnemonic = "wkey";
    else if(op == 0x15)
        instruction->mnemonic = "sdelay";
    else if(op == 0x18)
        instruction->mnemonic = "ssound";
    else if(op == 0x1E)
    {
        instruction->mnemonic = "add";
        instruction->reg(CHIP8_REG_I_ID, CHIP8_REG_I);
    }
    else if(op == 0x29)
        instruction->mnemonic = "font";
    else if(op == 0x30) // SuperChip only
        instruction->mnemonic = "xfont";
    else if(op == 0x33)
        instruction->mnemonic = "bcd";
    else if(op == 0x55)
        instruction->mnemonic = "stra";
    else if(op == 0x65)
        instruction->mnemonic = "ldra";
    else
        return false;

    instruction->reg((opcode & 0x0F00) >> 8);
    return true;
}

} // namespace REDasm
