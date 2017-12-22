#include "chip8.h"
#include "../../support/endianness.h"
#include "chip8printer.h"

#define SET_DECODE_TO(opmask, cb) _opcodemap[opmask] = [this](u16 opcode, const InstructionPtr& instruction) -> bool { return cb(opcode, instruction); };

namespace REDasm {

CHIP8Processor::CHIP8Processor(): _index(0)
{
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
    SET_DECODE_TO(0xF000, decodeFxxx);
}

const char *CHIP8Processor::name() const
{
    return "CHIP-8 Processor";
}

Printer *CHIP8Processor::createPrinter(DisassemblerFunctions *disassembler, SymbolTable *symboltable) const
{
    return new CHIP8Printer(disassembler, symboltable);
}

bool CHIP8Processor::decode(Buffer buffer, const InstructionPtr &instruction)
{
    u16 opcode = *reinterpret_cast<u16*>(buffer.data);
    Endianness::cfbe(opcode); // Chip8 is BE

    instruction->id = opcode;
    instruction->size = sizeof(u16);

    auto it = this->_opcodemap.find(opcode & 0xF000);

    if((it == this->_opcodemap.end()) || !it->second(opcode, instruction))
        return false;

    return ProcessorPlugin::decode(buffer, instruction);
}

bool CHIP8Processor::decode0xxx(u16 opcode, const InstructionPtr &instruction) const
{
    if(opcode == 0x00E0)
        instruction->mnemonic = "clr";
    else if(opcode == 0x00EE)
    {
        instruction->mnemonic = "rts";
        instruction->type = InstructionTypes::Stop;
    }
    else
    {
        instruction->mnemonic = "sys";
        instruction->type = InstructionTypes::Privileged;
        instruction->imm(opcode & 0x0FFF);
    }

    return true;
}

bool CHIP8Processor::decode1xxx(u16 opcode, const InstructionPtr &instruction) const
{
    instruction->mnemonic = "jump";
    instruction->type = InstructionTypes::Jump;

    instruction->imm(opcode & 0x0FFF);
    instruction->target_op(0);
    return true;
}

bool CHIP8Processor::decode2xxx(u16 opcode, const InstructionPtr &instruction) const
{
    instruction->mnemonic = "call";
    instruction->type = InstructionTypes::Call;

    instruction->imm(opcode & 0x0FFF);
    instruction->target_op(0);
    return true;
}

bool CHIP8Processor::decode3xxx(u16 opcode, const InstructionPtr &instruction) const
{
    instruction->mnemonic = "ske";
    instruction->type = InstructionTypes::Compare;

    instruction->reg((opcode & 0x0F00) >> 8);
    instruction->imm(opcode & 0x00FF);
    return true;
}

bool CHIP8Processor::decode4xxx(u16 opcode, const InstructionPtr &instruction) const
{
    instruction->mnemonic = "skne";
    instruction->type = InstructionTypes::Compare;

    instruction->reg((opcode & 0x0F00) >> 8);
    instruction->imm(opcode & 0x00FF);
    return true;
}

bool CHIP8Processor::decode5xxx(u16 opcode, const InstructionPtr &instruction) const
{
    if((opcode & 0x000F) != 0)
        return false;

    instruction->mnemonic = "skre";
    instruction->type = InstructionTypes::Compare;

    instruction->reg((opcode & 0x0F00) >> 8);
    instruction->reg((opcode & 0x00F0) >> 4);
    return true;
}

bool CHIP8Processor::decode6xxx(u16 opcode, const InstructionPtr &instruction) const
{
    instruction->mnemonic = "load";

    instruction->reg((opcode & 0x0F00) >> 8);
    instruction->imm(opcode & 0x00FF);
    return true;
}

bool CHIP8Processor::decode7xxx(u16 opcode, const InstructionPtr &instruction) const
{
    instruction->mnemonic = "add";
    instruction->type = InstructionTypes::Add;

    instruction->reg((opcode & 0x0F00) >> 8);
    instruction->imm(opcode & 0x00FF);
    return true;
}

bool CHIP8Processor::decode8xxx(u16 opcode, const InstructionPtr &instruction) const
{
    u8 op = opcode & 0x000F;

    if(op == 0x0)
        instruction->mnemonic = "move";
    else if(op == 0x1)
    {
        instruction->mnemonic = "or";
        instruction->type = InstructionTypes::Or;
    }
    else if(op == 0x2)
    {
        instruction->mnemonic = "and";
        instruction->type = InstructionTypes::And;
    }
    else if(op == 0x3)
    {
        instruction->mnemonic = "xor";
        instruction->type = InstructionTypes::Xor;
    }
    else if(op == 0x4)
    {
        instruction->mnemonic = "addr";
        instruction->type = InstructionTypes::Add;
    }
    else if(op == 0x5)
    {
        instruction->mnemonic = "sub";
        instruction->type = InstructionTypes::Sub;
    }
    else if(op == 0x6)
        instruction->mnemonic = "shr";
    else if(op == 0xE)
        instruction->mnemonic = "shl";
    else
        return false;

    instruction->reg((opcode & 0x0F00) >> 8);

    if(op < 0x6)
        instruction->reg((opcode & 0x00F0) >> 4);

    return true;
}

bool CHIP8Processor::decode9xxx(u16 opcode, const InstructionPtr &instruction) const
{
    if((opcode & 0x000F) != 0)
        return false;

    instruction->mnemonic = "skrne";
    instruction->type = InstructionTypes::Compare;

    instruction->reg((opcode & 0x0F00) >> 8);
    instruction->reg((opcode & 0x00F0) >> 4);
    return true;
}

bool CHIP8Processor::decodeAxxx(u16 opcode, const InstructionPtr &instruction) // const
{
    instruction->mnemonic = "loadi";
    instruction->type = InstructionTypes::Compare;

    this->_index = opcode & 0x0FFF;
    instruction->imm(this->_index);
    return true;
}

bool CHIP8Processor::decodeBxxx(u16 opcode, const InstructionPtr &instruction) const
{
    instruction->mnemonic = "jumpi";
    instruction->type = InstructionTypes::Jump;

    instruction->imm((opcode & 0x0FFF) + this->_index);
    return true;
}

bool CHIP8Processor::decodeCxxx(u16 opcode, const InstructionPtr &instruction) const
{
    instruction->mnemonic = "rand";

    instruction->reg((opcode & 0x0F00) >> 8);
    instruction->imm(opcode & 0x00FF);
    return true;
}

bool CHIP8Processor::decodeDxxx(u16 opcode, const InstructionPtr &instruction) const
{
    instruction->mnemonic = "draw";

    instruction->reg((opcode & 0x0F00) >> 8);
    instruction->reg((opcode & 0x00F0) >> 4);
    instruction->imm(opcode & 0x000F);
    return true;
}

bool CHIP8Processor::decodeFxxx(u16 opcode, const InstructionPtr &instruction) const
{
    u16 op = opcode & 0x00FF;

    if(op == 0x07)
        instruction->mnemonic = "moved";
    else if(op == 0x0A)
        instruction->mnemonic = "keyd";
    else if(op == 0x15)
        instruction->mnemonic = "loadd";
    else if(op == 0x18)
        instruction->mnemonic = "loads";
    else if(op == 0x1E)
    {
        instruction->mnemonic = "addi";
        instruction->type = InstructionTypes::Add;
    }
    else if(op == 0x29)
        instruction->mnemonic = "ldspr";
    else if(op == 0x33)
        instruction->mnemonic = "bcd";
    else if(op == 0x55)
        instruction->mnemonic = "stor";
    else if(op == 0x65)
        instruction->mnemonic = "read";
    else
        return false;

    instruction->reg((opcode & 0x0F00) >> 8);
    return true;
}

} // namespace REDasm
