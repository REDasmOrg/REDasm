#include "dalvik.h"
#include "dalvik_printer.h"
#include "dalvik_metadata.h"

#define SET_DECODE_OPCODE_TO(opcode) _opcodemap[0x##opcode] = [this](Buffer& buffer, const InstructionPtr& instruction) -> bool { return decode##opcode(buffer, instruction); }

#define SET_DECODE_TO(op) SET_DECODE_OPCODE_TO(op##0); SET_DECODE_OPCODE_TO(op##1); SET_DECODE_OPCODE_TO(op##2); SET_DECODE_OPCODE_TO(op##3); \
                          SET_DECODE_OPCODE_TO(op##4); SET_DECODE_OPCODE_TO(op##5); SET_DECODE_OPCODE_TO(op##6); SET_DECODE_OPCODE_TO(op##7); \
                          SET_DECODE_OPCODE_TO(op##8); SET_DECODE_OPCODE_TO(op##9); SET_DECODE_OPCODE_TO(op##A); SET_DECODE_OPCODE_TO(op##B); \
                          SET_DECODE_OPCODE_TO(op##C); SET_DECODE_OPCODE_TO(op##D); SET_DECODE_OPCODE_TO(op##E); SET_DECODE_OPCODE_TO(op##F)

namespace REDasm {

DalvikProcessor::DalvikProcessor(): ProcessorPlugin()
{
    SET_DECODE_TO(0); SET_DECODE_TO(1); SET_DECODE_TO(2); SET_DECODE_TO(3);
    SET_DECODE_TO(4); SET_DECODE_TO(5); SET_DECODE_TO(6); SET_DECODE_TO(7);
    SET_DECODE_TO(8); SET_DECODE_TO(9); SET_DECODE_TO(A); SET_DECODE_TO(B);
    SET_DECODE_TO(C); SET_DECODE_TO(D); SET_DECODE_TO(E); SET_DECODE_TO(F);
}

const char *DalvikProcessor::name() const
{
    return "Dalvik VM";
}

Printer *DalvikProcessor::createPrinter(DisassemblerFunctions *disassembler, SymbolTable *symboltable) const
{
    return new DalvikPrinter(disassembler, symboltable);
}

bool DalvikProcessor::decode(Buffer buffer, const InstructionPtr &instruction)
{
    u8 opcode = *buffer;

    auto it = this->_opcodemap.find(opcode);

    if(it == this->_opcodemap.end())
        return false;

    buffer++; // Skip opcode
    bool res = it->second(buffer, instruction);

    if(res)
        instruction->id = opcode;
    else
        instruction->size = sizeof(u16); // Dalvik uses always 16-bit aligned instructions

    ProcessorPlugin::decode(buffer, instruction);
    return res;
}

bool DalvikProcessor::decodeOp0(Buffer &buffer, const InstructionPtr &instruction, const std::string &mnemonic, u32 type) const
{
    RE_UNUSED(buffer);
    instruction->mnemonic = mnemonic;
    instruction->type = type;
    instruction->size = sizeof(u16);
    return true;
}

bool DalvikProcessor::decodeOp1(Buffer &buffer, const InstructionPtr &instruction, const std::string &mnemonic, u32 type) const
{
    instruction->mnemonic = mnemonic;
    instruction->type = type;
    instruction->size = sizeof(u16);
    instruction->reg(*buffer & 0xF);
    return true;
}

bool DalvikProcessor::decodeOp2(Buffer &buffer, const InstructionPtr &instruction, const std::string &mnemonic) const
{
    instruction->mnemonic = mnemonic;
    instruction->size = sizeof(u16);
    instruction->reg(*buffer & 0xF);
    instruction->reg((*buffer & 0xF0) >> 4);
    return true;
}

bool DalvikProcessor::decodeOp3(Buffer &buffer, const InstructionPtr &instruction, const std::string &mnemonic, u32 type) const
{
    instruction->mnemonic = mnemonic;
    instruction->size = sizeof(u16) * 2;
    instruction->reg(*buffer++);
    instruction->reg(*buffer++);
    instruction->reg(*buffer);
    return true;
}

bool DalvikProcessor::decodeOp2_s(Buffer &buffer, const InstructionPtr &instruction, const std::string &mnemonic) const
{
    instruction->mnemonic = mnemonic;
    instruction->size = sizeof(u16) * 2;
    instruction->reg(*buffer++);
    instruction->imm(this->read<u16>(buffer), DalvikOperands::StringIndex);
    return true;
}

bool DalvikProcessor::decodeOp2_t(Buffer &buffer, const InstructionPtr &instruction, const std::string &mnemonic) const
{
    instruction->mnemonic = mnemonic;
    instruction->size = sizeof(u16) * 2;
    instruction->reg(*buffer++);
    instruction->imm(this->read<u16>(buffer), DalvikOperands::TypeIndex);
    return true;
}

bool DalvikProcessor::decodeOp2_f(Buffer &buffer, const InstructionPtr &instruction, const std::string &mnemonic, u32 type) const
{
    instruction->mnemonic = mnemonic;
    instruction->type = type;
    instruction->size = sizeof(u16) * 2;
    instruction->reg(*buffer++);
    instruction->imm(this->read<u16>(buffer), DalvikOperands::FieldIndex);
    return true;
}

bool DalvikProcessor::decodeOp2_16(Buffer &buffer, const InstructionPtr &instruction, const std::string &mnemonic) const
{
    instruction->mnemonic = mnemonic;
    instruction->size = sizeof(u16) * 2;
    instruction->reg(*buffer++);
    instruction->reg(this->read<u16>(buffer));
    return true;
}

bool DalvikProcessor::decodeOp2_imm4(Buffer &buffer, const InstructionPtr &instruction, const std::string &mnemonic) const
{
    instruction->mnemonic = mnemonic;
    instruction->size = sizeof(u16);
    instruction->reg(*buffer & 0xF);
    instruction->imm((*buffer & 0xF0) >> 4);
    return true;
}

bool DalvikProcessor::decodeOp2_imm16(Buffer &buffer, const InstructionPtr &instruction, const std::string &mnemonic) const
{
    instruction->mnemonic = mnemonic;
    instruction->size = sizeof(u16) * 2;
    instruction->reg(*buffer++);
    instruction->imm(this->read<u16>(buffer));
    return true;
}

bool DalvikProcessor::decodeOp2_imm32(Buffer &buffer, const InstructionPtr &instruction, const std::string &mnemonic) const
{
    instruction->mnemonic = mnemonic;
    instruction->size = sizeof(u16) * 3;
    instruction->reg(*buffer++);
    instruction->imm(this->read<u32>(buffer));
    return true;
}

bool DalvikProcessor::decodeOp3_f(Buffer &buffer, const InstructionPtr &instruction, const std::string &mnemonic, u32 type) const
{
    instruction->mnemonic = mnemonic;
    instruction->type = type;
    instruction->size = sizeof(u16) * 2;
    instruction->reg(*buffer & 0xF);
    instruction->reg((*buffer++ & 0xF0) >> 4);
    instruction->imm(this->read<u16>(buffer), DalvikOperands::FieldIndex);
    return true;
}

bool DalvikProcessor::decodeOp3_t(Buffer &buffer, const InstructionPtr &instruction, const std::string &mnemonic, u32 type) const
{
    instruction->mnemonic = mnemonic;
    instruction->type = type;
    instruction->size = sizeof(u16) * 2;
    instruction->reg(*buffer & 0xF);
    instruction->reg((*buffer++ & 0xF0) >> 4);
    instruction->imm(this->read<u16>(buffer), DalvikOperands::TypeIndex);
    return true;
}

bool DalvikProcessor::decodeIfOp2(Buffer &buffer, const InstructionPtr &instruction, const std::string &cond) const
{
    instruction->mnemonic = "if-" + cond;
    instruction->type = InstructionTypes::Jump | InstructionTypes::Conditional;
    instruction->size = sizeof(u16) * 2;
    instruction->reg(*buffer++ & 0xF);
    instruction->imm(instruction->address + (sizeof(u16) * this->read<s16>(buffer)));
    instruction->target_op(1);
    return true;
}

bool DalvikProcessor::decodeIfOp3(Buffer &buffer, const InstructionPtr &instruction, const std::string &cond) const
{
    instruction->mnemonic = "if-" + cond;
    instruction->type = InstructionTypes::Jump | InstructionTypes::Conditional;
    instruction->size = sizeof(u16) * 2;
    instruction->reg(*buffer & 0xF);
    instruction->reg((*buffer++ & 0xF0) >> 4);
    instruction->imm(instruction->address + (sizeof(u16) * this->read<s16>(buffer)));
    instruction->target_op(2);
    return true;
}

bool DalvikProcessor::decodeInvoke(Buffer &buffer, const InstructionPtr &instruction, const std::string &kind) const
{
    u8 b = *buffer++;
    u8 argc = b >> 4;
    bool needsfirst = true;

    instruction->size = sizeof(u16) * 2;

    if((argc > 4) && ((argc % 4) == 1))
    {
        needsfirst = false;
        instruction->reg(b & 0xF, DalvikOperands::ParameterFirst);
        argc--;
    }

    u16 midx = this->read<u16>(buffer);

    if(argc)
    {
        u16 argwords = std::max(1, argc / 4);
        instruction->size += sizeof(u16) * argwords;

        for(u16 argword = 0, c = 0; (c < argc) && (argword < argwords); argword++)
        {
            for(u8 i = 0; (c < argc) && (i < (4 * 8)); i += 4, c++)
            {
                register_t reg = (argword & (0xF << i)) >> i;
                u64 regtype = DalvikOperands::Normal;

                if(needsfirst && !c)
                    regtype |= DalvikOperands::ParameterFirst;

                if(c == (argc - 1))
                    regtype |= DalvikOperands::ParameterLast;

                instruction->reg(reg, regtype);
            }
        }
    }

    instruction->imm(midx, DalvikOperands::MethodIndex);
    instruction->type = InstructionTypes::Call;
    instruction->mnemonic = "invoke-" + kind;
    return true;
}

bool DalvikProcessor::decode00(Buffer &buffer, const InstructionPtr &instruction) const { return this->decodeOp0(buffer, instruction, "nop"); }
bool DalvikProcessor::decode01(Buffer &buffer, const InstructionPtr &instruction) const { return this->decodeOp2(buffer, instruction, "move"); }
bool DalvikProcessor::decode02(Buffer &buffer, const InstructionPtr &instruction) const { return this->decodeOp2_16(buffer, instruction, "move/from16"); }

bool DalvikProcessor::decode03(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikProcessor::decode04(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikProcessor::decode05(Buffer &buffer, const InstructionPtr &instruction) const { return this->decodeOp2_16(buffer, instruction, "move-wide/from16"); }

bool DalvikProcessor::decode06(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikProcessor::decode07(Buffer &buffer, const InstructionPtr &instruction) const { return this->decodeOp2(buffer, instruction, "move-object"); }
bool DalvikProcessor::decode08(Buffer &buffer, const InstructionPtr &instruction) const { return this->decodeOp2_16(buffer, instruction, "move-object/from16"); }

bool DalvikProcessor::decode09(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikProcessor::decode0A(Buffer &buffer, const InstructionPtr &instruction) const { return this->decodeOp1(buffer, instruction, "move-result"); }
bool DalvikProcessor::decode0B(Buffer &buffer, const InstructionPtr &instruction) const { return this->decodeOp1(buffer, instruction, "move-result-wide");}
bool DalvikProcessor::decode0C(Buffer &buffer, const InstructionPtr &instruction) const { return this->decodeOp1(buffer, instruction, "move-result-object");}
bool DalvikProcessor::decode0D(Buffer &buffer, const InstructionPtr &instruction) const { return this->decodeOp1(buffer, instruction, "move-exception"); }
bool DalvikProcessor::decode0E(Buffer &buffer, const InstructionPtr &instruction) const { return this->decodeOp0(buffer, instruction, "return-void", InstructionTypes::Stop); }
bool DalvikProcessor::decode0F(Buffer &buffer, const InstructionPtr &instruction) const { return this->decodeOp1(buffer, instruction, "return", InstructionTypes::Stop); }
bool DalvikProcessor::decode10(Buffer &buffer, const InstructionPtr &instruction) const { return this->decodeOp1(buffer, instruction, "return-wide", InstructionTypes::Stop); }
bool DalvikProcessor::decode11(Buffer &buffer, const InstructionPtr &instruction) const { return this->decodeOp1(buffer, instruction, "return-object", InstructionTypes::Stop); }

bool DalvikProcessor::decode12(Buffer &buffer, const InstructionPtr &instruction) const { return this->decodeOp2_imm4(buffer, instruction, "const/4"); }
bool DalvikProcessor::decode13(Buffer &buffer, const InstructionPtr &instruction) const { return this->decodeOp2_imm16(buffer, instruction, "const/16"); }
bool DalvikProcessor::decode14(Buffer &buffer, const InstructionPtr &instruction) const { return this->decodeOp2_imm32(buffer, instruction, "const/16"); }

bool DalvikProcessor::decode15(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikProcessor::decode16(Buffer &buffer, const InstructionPtr &instruction) const { return this->decodeOp2_imm16(buffer, instruction, "const-wide/16"); }
bool DalvikProcessor::decode17(Buffer &buffer, const InstructionPtr &instruction) const { return this->decodeOp2_imm32(buffer, instruction, "const-wide/32");  }

bool DalvikProcessor::decode18(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikProcessor::decode19(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikProcessor::decode1A(Buffer &buffer, const InstructionPtr &instruction) const { return this->decodeOp2_s(buffer, instruction, "const-string"); }

bool DalvikProcessor::decode1B(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikProcessor::decode1C(Buffer &buffer, const InstructionPtr &instruction) const { return this->decodeOp2_t(buffer, instruction, "const-class"); }
bool DalvikProcessor::decode1D(Buffer &buffer, const InstructionPtr &instruction) const { return this->decodeOp1(buffer, instruction, "monitor-enter"); }
bool DalvikProcessor::decode1E(Buffer &buffer, const InstructionPtr &instruction) const { return this->decodeOp0(buffer, instruction, "monitor-exit"); }
bool DalvikProcessor::decode1F(Buffer &buffer, const InstructionPtr &instruction) const { return this->decodeOp2_t(buffer, instruction, "check-cast"); }
bool DalvikProcessor::decode20(Buffer &buffer, const InstructionPtr &instruction) const { return this->decodeOp3_t(buffer, instruction, "instance-of"); }
bool DalvikProcessor::decode21(Buffer &buffer, const InstructionPtr &instruction) const { return this->decodeOp2(buffer, instruction, "array-length"); }
bool DalvikProcessor::decode22(Buffer &buffer, const InstructionPtr &instruction) const { return this->decodeOp2_t(buffer, instruction, "new-instance"); }
bool DalvikProcessor::decode23(Buffer &buffer, const InstructionPtr &instruction) const { return this->decodeOp3_t(buffer, instruction, "new-array"); }

bool DalvikProcessor::decode24(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikProcessor::decode25(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikProcessor::decode26(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikProcessor::decode27(Buffer &buffer, const InstructionPtr &instruction) const { return this->decodeOp1(buffer, instruction, "throw-vx"); }

bool DalvikProcessor::decode28(Buffer &buffer, const InstructionPtr &instruction) const
{
    instruction->mnemonic = "goto";
    instruction->type = InstructionTypes::Jump;
    instruction->size = sizeof(u16);
    instruction->imm(instruction->address + (static_cast<s8>(*buffer) * sizeof(u16)));
    instruction->target_op(0);
    return true;
}

bool DalvikProcessor::decode29(Buffer &buffer, const InstructionPtr &instruction) const
{
    instruction->mnemonic = "goto/16";
    instruction->type = InstructionTypes::Jump;
    instruction->size = sizeof(u16) * 2;
    instruction->imm(instruction->address + (this->read<s16>(buffer) * sizeof(u16)));
    instruction->target_op(0);
    return true;
}

bool DalvikProcessor::decode2A(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikProcessor::decode2B(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikProcessor::decode2C(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikProcessor::decode2D(Buffer &buffer, const InstructionPtr &instruction) const { return this->decodeOp3(buffer, instruction, "cmpl-float"); }
bool DalvikProcessor::decode2E(Buffer &buffer, const InstructionPtr &instruction) const { return this->decodeOp3(buffer, instruction, "cmpg-float"); }
bool DalvikProcessor::decode2F(Buffer &buffer, const InstructionPtr &instruction) const { return this->decodeOp3(buffer, instruction, "cmpl-double"); }
bool DalvikProcessor::decode30(Buffer &buffer, const InstructionPtr &instruction) const { return this->decodeOp3(buffer, instruction, "cmpg-double"); }
bool DalvikProcessor::decode31(Buffer &buffer, const InstructionPtr &instruction) const { return this->decodeOp3(buffer, instruction, "cmp-long"); }
bool DalvikProcessor::decode32(Buffer &buffer, const InstructionPtr &instruction) const { return this->decodeIfOp3(buffer, instruction, "eq"); }
bool DalvikProcessor::decode33(Buffer &buffer, const InstructionPtr &instruction) const { return this->decodeIfOp3(buffer, instruction, "ne"); }
bool DalvikProcessor::decode34(Buffer &buffer, const InstructionPtr &instruction) const { return this->decodeIfOp3(buffer, instruction, "lt"); }
bool DalvikProcessor::decode35(Buffer &buffer, const InstructionPtr &instruction) const { return this->decodeIfOp3(buffer, instruction, "ge"); }
bool DalvikProcessor::decode36(Buffer &buffer, const InstructionPtr &instruction) const { return this->decodeIfOp3(buffer, instruction, "gt"); }
bool DalvikProcessor::decode37(Buffer &buffer, const InstructionPtr &instruction) const { return this->decodeIfOp3(buffer, instruction, "le"); }
bool DalvikProcessor::decode38(Buffer &buffer, const InstructionPtr &instruction) const { return this->decodeIfOp3(buffer, instruction, "eqz"); }
bool DalvikProcessor::decode39(Buffer &buffer, const InstructionPtr &instruction) const { return this->decodeIfOp2(buffer, instruction, "nez"); }
bool DalvikProcessor::decode3A(Buffer &buffer, const InstructionPtr &instruction) const { return this->decodeIfOp2(buffer, instruction, "ltz"); }
bool DalvikProcessor::decode3B(Buffer &buffer, const InstructionPtr &instruction) const { return this->decodeIfOp2(buffer, instruction, "gez"); }
bool DalvikProcessor::decode3C(Buffer &buffer, const InstructionPtr &instruction) const { return this->decodeIfOp2(buffer, instruction, "gtz"); }
bool DalvikProcessor::decode3D(Buffer &buffer, const InstructionPtr &instruction) const { return this->decodeIfOp2(buffer, instruction, "lez"); }

bool DalvikProcessor::decode3E(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikProcessor::decode3F(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikProcessor::decode40(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikProcessor::decode41(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikProcessor::decode42(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikProcessor::decode43(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikProcessor::decode44(Buffer &buffer, const InstructionPtr &instruction) const { return this->decodeOp3(buffer, instruction, "aget", InstructionTypes::Load); }
bool DalvikProcessor::decode45(Buffer &buffer, const InstructionPtr &instruction) const { return this->decodeOp3(buffer, instruction, "aget-wide", InstructionTypes::Load); }
bool DalvikProcessor::decode46(Buffer &buffer, const InstructionPtr &instruction) const { return this->decodeOp3(buffer, instruction, "aget-object", InstructionTypes::Load); }
bool DalvikProcessor::decode47(Buffer &buffer, const InstructionPtr &instruction) const { return this->decodeOp3(buffer, instruction, "aget-boolean", InstructionTypes::Load); }
bool DalvikProcessor::decode48(Buffer &buffer, const InstructionPtr &instruction) const { return this->decodeOp3(buffer, instruction, "aget-byte", InstructionTypes::Load); }
bool DalvikProcessor::decode49(Buffer &buffer, const InstructionPtr &instruction) const { return this->decodeOp3(buffer, instruction, "aget-char", InstructionTypes::Load); }
bool DalvikProcessor::decode4A(Buffer &buffer, const InstructionPtr &instruction) const { return this->decodeOp3(buffer, instruction, "aget-short", InstructionTypes::Load); }
bool DalvikProcessor::decode4B(Buffer &buffer, const InstructionPtr &instruction) const { return this->decodeOp3(buffer, instruction, "aput", InstructionTypes::Store); }
bool DalvikProcessor::decode4C(Buffer &buffer, const InstructionPtr &instruction) const { return this->decodeOp3(buffer, instruction, "aput-wide", InstructionTypes::Store); }
bool DalvikProcessor::decode4D(Buffer &buffer, const InstructionPtr &instruction) const { return this->decodeOp3(buffer, instruction, "aput-object", InstructionTypes::Store); }
bool DalvikProcessor::decode4E(Buffer &buffer, const InstructionPtr &instruction) const { return this->decodeOp3(buffer, instruction, "aput-boolean", InstructionTypes::Store); }
bool DalvikProcessor::decode4F(Buffer &buffer, const InstructionPtr &instruction) const { return this->decodeOp3(buffer, instruction, "aput-byte", InstructionTypes::Store); }
bool DalvikProcessor::decode50(Buffer &buffer, const InstructionPtr &instruction) const { return this->decodeOp3(buffer, instruction, "aput-char", InstructionTypes::Store); }
bool DalvikProcessor::decode51(Buffer &buffer, const InstructionPtr &instruction) const { return this->decodeOp3(buffer, instruction, "aput-short", InstructionTypes::Store); }
bool DalvikProcessor::decode52(Buffer &buffer, const InstructionPtr &instruction) const { return this->decodeOp3_f(buffer, instruction, "iget", InstructionTypes::Load); }
bool DalvikProcessor::decode53(Buffer &buffer, const InstructionPtr &instruction) const { return this->decodeOp3_f(buffer, instruction, "iget-wide", InstructionTypes::Load); }
bool DalvikProcessor::decode54(Buffer &buffer, const InstructionPtr &instruction) const { return this->decodeOp3_f(buffer, instruction, "iget-object", InstructionTypes::Load); }
bool DalvikProcessor::decode55(Buffer &buffer, const InstructionPtr &instruction) const { return this->decodeOp3_f(buffer, instruction, "iget-boolean", InstructionTypes::Load); }
bool DalvikProcessor::decode56(Buffer &buffer, const InstructionPtr &instruction) const { return this->decodeOp3_f(buffer, instruction, "iget-byte", InstructionTypes::Load); }
bool DalvikProcessor::decode57(Buffer &buffer, const InstructionPtr &instruction) const { return this->decodeOp3_f(buffer, instruction, "iget-char", InstructionTypes::Load); }
bool DalvikProcessor::decode58(Buffer &buffer, const InstructionPtr &instruction) const { return this->decodeOp3_f(buffer, instruction, "iget-short", InstructionTypes::Load); }
bool DalvikProcessor::decode59(Buffer &buffer, const InstructionPtr &instruction) const { return this->decodeOp3_f(buffer, instruction, "iput", InstructionTypes::Store); }
bool DalvikProcessor::decode5A(Buffer &buffer, const InstructionPtr &instruction) const { return this->decodeOp3_f(buffer, instruction, "iput-wide", InstructionTypes::Store); }
bool DalvikProcessor::decode5B(Buffer &buffer, const InstructionPtr &instruction) const { return this->decodeOp3_f(buffer, instruction, "iput-object", InstructionTypes::Store); }
bool DalvikProcessor::decode5C(Buffer &buffer, const InstructionPtr &instruction) const { return this->decodeOp3_f(buffer, instruction, "iput-boolean", InstructionTypes::Store); }
bool DalvikProcessor::decode5D(Buffer &buffer, const InstructionPtr &instruction) const { return this->decodeOp3_f(buffer, instruction, "iput-byte", InstructionTypes::Store); }
bool DalvikProcessor::decode5E(Buffer &buffer, const InstructionPtr &instruction) const { return this->decodeOp3_f(buffer, instruction, "iput-char", InstructionTypes::Store); }
bool DalvikProcessor::decode5F(Buffer &buffer, const InstructionPtr &instruction) const { return this->decodeOp3_f(buffer, instruction, "iput-short", InstructionTypes::Store); }
bool DalvikProcessor::decode60(Buffer &buffer, const InstructionPtr &instruction) const { return this->decodeOp2_f(buffer, instruction, "sget", InstructionTypes::Load); }
bool DalvikProcessor::decode61(Buffer &buffer, const InstructionPtr &instruction) const { return this->decodeOp2_f(buffer, instruction, "sget-wide", InstructionTypes::Load); }
bool DalvikProcessor::decode62(Buffer &buffer, const InstructionPtr &instruction) const { return this->decodeOp2_f(buffer, instruction, "sget-object", InstructionTypes::Load); }
bool DalvikProcessor::decode63(Buffer &buffer, const InstructionPtr &instruction) const { return this->decodeOp2_f(buffer, instruction, "sget-boolean", InstructionTypes::Load); }
bool DalvikProcessor::decode64(Buffer &buffer, const InstructionPtr &instruction) const { return this->decodeOp2_f(buffer, instruction, "sget-byte", InstructionTypes::Load); }
bool DalvikProcessor::decode65(Buffer &buffer, const InstructionPtr &instruction) const { return this->decodeOp2_f(buffer, instruction, "sget-char", InstructionTypes::Load); }
bool DalvikProcessor::decode66(Buffer &buffer, const InstructionPtr &instruction) const { return this->decodeOp2_f(buffer, instruction, "sget-short", InstructionTypes::Load); }
bool DalvikProcessor::decode67(Buffer &buffer, const InstructionPtr &instruction) const { return this->decodeOp2_f(buffer, instruction, "sput", InstructionTypes::Store); }
bool DalvikProcessor::decode68(Buffer &buffer, const InstructionPtr &instruction) const { return this->decodeOp2_f(buffer, instruction, "sput-wide", InstructionTypes::Store); }
bool DalvikProcessor::decode69(Buffer &buffer, const InstructionPtr &instruction) const { return this->decodeOp2_f(buffer, instruction, "sput-object", InstructionTypes::Store); }
bool DalvikProcessor::decode6A(Buffer &buffer, const InstructionPtr &instruction) const { return this->decodeOp2_f(buffer, instruction, "sput-boolean", InstructionTypes::Store); }
bool DalvikProcessor::decode6B(Buffer &buffer, const InstructionPtr &instruction) const { return this->decodeOp2_f(buffer, instruction, "sput-byte", InstructionTypes::Store); }
bool DalvikProcessor::decode6C(Buffer &buffer, const InstructionPtr &instruction) const { return this->decodeOp2_f(buffer, instruction, "sput-char", InstructionTypes::Store); }
bool DalvikProcessor::decode6D(Buffer &buffer, const InstructionPtr &instruction) const { return this->decodeOp2_f(buffer, instruction, "sput-short", InstructionTypes::Store); }
bool DalvikProcessor::decode6E(Buffer &buffer, const InstructionPtr &instruction) const { return this->decodeInvoke(buffer, instruction, "virtual"); }
bool DalvikProcessor::decode6F(Buffer &buffer, const InstructionPtr &instruction) const { return this->decodeInvoke(buffer, instruction, "super"); }
bool DalvikProcessor::decode70(Buffer &buffer, const InstructionPtr &instruction) const { return this->decodeInvoke(buffer, instruction, "direct"); }
bool DalvikProcessor::decode71(Buffer &buffer, const InstructionPtr &instruction) const { return this->decodeInvoke(buffer, instruction, "static"); }
bool DalvikProcessor::decode72(Buffer &buffer, const InstructionPtr &instruction) const { return this->decodeInvoke(buffer, instruction, "interface"); }

bool DalvikProcessor::decode73(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikProcessor::decode74(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikProcessor::decode75(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikProcessor::decode76(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikProcessor::decode77(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikProcessor::decode78(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikProcessor::decode79(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikProcessor::decode7A(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikProcessor::decode7B(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikProcessor::decode7C(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikProcessor::decode7D(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikProcessor::decode7E(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikProcessor::decode7F(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikProcessor::decode80(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikProcessor::decode81(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikProcessor::decode82(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikProcessor::decode83(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikProcessor::decode84(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikProcessor::decode85(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikProcessor::decode86(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikProcessor::decode87(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikProcessor::decode88(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikProcessor::decode89(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikProcessor::decode8A(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikProcessor::decode8B(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikProcessor::decode8C(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikProcessor::decode8D(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikProcessor::decode8E(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikProcessor::decode8F(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikProcessor::decode90(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikProcessor::decode91(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikProcessor::decode92(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikProcessor::decode93(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikProcessor::decode94(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikProcessor::decode95(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikProcessor::decode96(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikProcessor::decode97(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikProcessor::decode98(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikProcessor::decode99(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikProcessor::decode9A(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikProcessor::decode9B(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikProcessor::decode9C(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikProcessor::decode9D(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikProcessor::decode9E(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikProcessor::decode9F(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikProcessor::decodeA0(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikProcessor::decodeA1(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikProcessor::decodeA2(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikProcessor::decodeA3(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikProcessor::decodeA4(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikProcessor::decodeA5(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikProcessor::decodeA6(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikProcessor::decodeA7(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikProcessor::decodeA8(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikProcessor::decodeA9(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikProcessor::decodeAA(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikProcessor::decodeAB(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikProcessor::decodeAC(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikProcessor::decodeAD(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikProcessor::decodeAE(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikProcessor::decodeAF(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikProcessor::decodeB0(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikProcessor::decodeB1(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikProcessor::decodeB2(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikProcessor::decodeB3(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikProcessor::decodeB4(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikProcessor::decodeB5(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikProcessor::decodeB6(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikProcessor::decodeB7(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikProcessor::decodeB8(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikProcessor::decodeB9(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikProcessor::decodeBA(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikProcessor::decodeBB(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikProcessor::decodeBC(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikProcessor::decodeBD(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikProcessor::decodeBE(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikProcessor::decodeBF(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikProcessor::decodeC0(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikProcessor::decodeC1(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikProcessor::decodeC2(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikProcessor::decodeC3(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikProcessor::decodeC4(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikProcessor::decodeC5(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikProcessor::decodeC6(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikProcessor::decodeC7(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikProcessor::decodeC8(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikProcessor::decodeC9(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikProcessor::decodeCA(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikProcessor::decodeCB(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikProcessor::decodeCC(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikProcessor::decodeCD(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikProcessor::decodeCE(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikProcessor::decodeCF(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikProcessor::decodeD0(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikProcessor::decodeD1(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikProcessor::decodeD2(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikProcessor::decodeD3(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikProcessor::decodeD4(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikProcessor::decodeD5(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikProcessor::decodeD6(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikProcessor::decodeD7(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikProcessor::decodeD8(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikProcessor::decodeD9(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikProcessor::decodeDA(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikProcessor::decodeDB(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikProcessor::decodeDC(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikProcessor::decodeDD(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikProcessor::decodeDE(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikProcessor::decodeDF(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikProcessor::decodeE0(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikProcessor::decodeE1(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikProcessor::decodeE2(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikProcessor::decodeE3(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikProcessor::decodeE4(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikProcessor::decodeE5(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikProcessor::decodeE6(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikProcessor::decodeE7(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikProcessor::decodeE8(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikProcessor::decodeE9(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikProcessor::decodeEA(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikProcessor::decodeEB(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikProcessor::decodeEC(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikProcessor::decodeED(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikProcessor::decodeEE(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikProcessor::decodeEF(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikProcessor::decodeF0(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikProcessor::decodeF1(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikProcessor::decodeF2(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikProcessor::decodeF3(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikProcessor::decodeF4(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikProcessor::decodeF5(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikProcessor::decodeF6(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikProcessor::decodeF7(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikProcessor::decodeF8(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikProcessor::decodeF9(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikProcessor::decodeFA(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikProcessor::decodeFB(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikProcessor::decodeFC(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikProcessor::decodeFD(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikProcessor::decodeFE(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikProcessor::decodeFF(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

} // namespace REDasm
