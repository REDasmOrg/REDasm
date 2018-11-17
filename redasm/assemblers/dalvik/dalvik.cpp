#include "dalvik.h"
#include "../../formats/dex/dex.h"
#include "dalvik_printer.h"
#include "dalvik_opcodes.h"
#include "dalvik_metadata.h"
#include "dalvik_algorithm.h"

#define SET_DECODE_OPCODE_TO(opcode) m_opcodemap[0x##opcode] = [this](BufferRef& buffer, const InstructionPtr& instruction) -> bool { return decode##opcode(buffer, instruction); }

#define SET_DECODE_TO(op) SET_DECODE_OPCODE_TO(op##0); SET_DECODE_OPCODE_TO(op##1); SET_DECODE_OPCODE_TO(op##2); SET_DECODE_OPCODE_TO(op##3); \
                          SET_DECODE_OPCODE_TO(op##4); SET_DECODE_OPCODE_TO(op##5); SET_DECODE_OPCODE_TO(op##6); SET_DECODE_OPCODE_TO(op##7); \
                          SET_DECODE_OPCODE_TO(op##8); SET_DECODE_OPCODE_TO(op##9); SET_DECODE_OPCODE_TO(op##A); SET_DECODE_OPCODE_TO(op##B); \
                          SET_DECODE_OPCODE_TO(op##C); SET_DECODE_OPCODE_TO(op##D); SET_DECODE_OPCODE_TO(op##E); SET_DECODE_OPCODE_TO(op##F)

namespace REDasm {

DalvikAssembler::DalvikAssembler(): AssemblerPlugin()
{
    SET_DECODE_TO(0); SET_DECODE_TO(1); SET_DECODE_TO(2); SET_DECODE_TO(3);
    SET_DECODE_TO(4); SET_DECODE_TO(5); SET_DECODE_TO(6); SET_DECODE_TO(7);
    SET_DECODE_TO(8); SET_DECODE_TO(9); SET_DECODE_TO(A); SET_DECODE_TO(B);
    SET_DECODE_TO(C); SET_DECODE_TO(D); SET_DECODE_TO(E); SET_DECODE_TO(F);
}

const char *DalvikAssembler::name() const { return "Dalvik VM"; }
Printer *DalvikAssembler::createPrinter(DisassemblerAPI *disassembler) const { return new DalvikPrinter(disassembler); }
AssemblerAlgorithm *DalvikAssembler::createAlgorithm(DisassemblerAPI *disassembler) { return new DalvikAlgorithm(disassembler, this); }

bool DalvikAssembler::decodeInstruction(BufferRef& buffer, const InstructionPtr &instruction)
{
    instruction->id = *buffer;

    auto it = m_opcodemap.find(instruction->id);

    if(it == m_opcodemap.end())
        return false;

    bool res = it->second(++buffer, instruction);

    if(!res)
        instruction->size = sizeof(u16); // Dalvik uses always 16-bit aligned instructions

    return res;
}

bool DalvikAssembler::decodeOp0(BufferRef &buffer, const InstructionPtr &instruction, const std::string &mnemonic, u32 type) const
{
    RE_UNUSED(buffer);
    instruction->mnemonic = mnemonic;
    instruction->type = type;
    instruction->size = sizeof(u16);
    return true;
}

bool DalvikAssembler::decodeOp1(BufferRef &buffer, const InstructionPtr &instruction, const std::string &mnemonic, u32 type) const
{
    instruction->mnemonic = mnemonic;
    instruction->type = type;
    instruction->size = sizeof(u16);
    instruction->reg(*buffer & 0xF);
    return true;
}

bool DalvikAssembler::decodeOp2(BufferRef &buffer, const InstructionPtr &instruction, const std::string &mnemonic) const
{
    instruction->mnemonic = mnemonic;
    instruction->size = sizeof(u16);
    instruction->reg(*buffer & 0xF);
    instruction->reg((*buffer & 0xF0) >> 4);
    return true;
}

bool DalvikAssembler::decodeOp3(BufferRef &buffer, const InstructionPtr &instruction, const std::string &mnemonic, u32 type) const
{
    instruction->mnemonic = mnemonic;
    instruction->type = type;
    instruction->size = sizeof(u16) * 2;
    instruction->reg(*buffer++);
    instruction->reg(*buffer++);
    instruction->reg(*buffer);
    return true;
}

bool DalvikAssembler::decodeOp2_s(BufferRef &buffer, const InstructionPtr &instruction, const std::string &mnemonic) const
{
    instruction->mnemonic = mnemonic;
    instruction->size = sizeof(u16) * 2;
    instruction->reg(*buffer++);
    instruction->imm(static_cast<u16>(buffer), DalvikOperands::StringIndex);
    return true;
}

bool DalvikAssembler::decodeOp2_t(BufferRef &buffer, const InstructionPtr &instruction, const std::string &mnemonic) const
{
    instruction->mnemonic = mnemonic;
    instruction->size = sizeof(u16) * 2;
    instruction->reg(*buffer++);
    instruction->imm(static_cast<u16>(buffer), DalvikOperands::TypeIndex);
    return true;
}

bool DalvikAssembler::decodeOp2_f(BufferRef &buffer, const InstructionPtr &instruction, const std::string &mnemonic, u32 type) const
{
    instruction->mnemonic = mnemonic;
    instruction->type = type;
    instruction->size = sizeof(u16) * 2;
    instruction->reg(*buffer++);
    instruction->imm(static_cast<u16>(buffer), DalvikOperands::FieldIndex);
    return true;
}

bool DalvikAssembler::decodeOp2_16(BufferRef &buffer, const InstructionPtr &instruction, const std::string &mnemonic) const
{
    instruction->mnemonic = mnemonic;
    instruction->size = sizeof(u16) * 2;
    instruction->reg(*buffer++);
    instruction->reg(static_cast<u16>(buffer));
    return true;
}

bool DalvikAssembler::decodeOp2_imm4(BufferRef &buffer, const InstructionPtr &instruction, const std::string &mnemonic) const
{
    instruction->mnemonic = mnemonic;
    instruction->size = sizeof(u16);
    instruction->reg(*buffer & 0xF);
    instruction->imm((*buffer & 0xF0) >> 4);
    return true;
}

bool DalvikAssembler::decodeOp2_imm16(BufferRef &buffer, const InstructionPtr &instruction, const std::string &mnemonic) const
{
    instruction->mnemonic = mnemonic;
    instruction->size = sizeof(u16) * 2;
    instruction->reg(*buffer++);
    instruction->imm(static_cast<u16>(buffer));
    return true;
}

bool DalvikAssembler::decodeOp2_imm32(BufferRef &buffer, const InstructionPtr &instruction, const std::string &mnemonic) const
{
    instruction->mnemonic = mnemonic;
    instruction->size = sizeof(u16) * 3;
    instruction->reg(*buffer++);
    instruction->imm(static_cast<u32>(buffer));
    return true;
}

bool DalvikAssembler::decodeOp3_f(BufferRef &buffer, const InstructionPtr &instruction, const std::string &mnemonic, u32 type) const
{
    instruction->mnemonic = mnemonic;
    instruction->type = type;
    instruction->size = sizeof(u16) * 2;
    instruction->reg(*buffer & 0xF);
    instruction->reg((*buffer++ & 0xF0) >> 4);
    instruction->imm(static_cast<u16>(buffer), DalvikOperands::FieldIndex);
    return true;
}

bool DalvikAssembler::decodeOp3_t(BufferRef &buffer, const InstructionPtr &instruction, const std::string &mnemonic, u32 type) const
{
    instruction->mnemonic = mnemonic;
    instruction->type = type;
    instruction->size = sizeof(u16) * 2;
    instruction->reg(*buffer & 0xF);
    instruction->reg((*buffer++ & 0xF0) >> 4);
    instruction->imm(static_cast<u16>(buffer), DalvikOperands::TypeIndex);
    return true;
}

bool DalvikAssembler::decodeOp3_imm8(BufferRef &buffer, const InstructionPtr &instruction, const std::string &mnemonic) const
{
    instruction->mnemonic = mnemonic;
    instruction->size = sizeof(u16) * 2;
    instruction->reg(*buffer++);
    instruction->reg(*buffer++);
    instruction->imm(*buffer);
    return true;
}

bool DalvikAssembler::decodeOp3_imm16(BufferRef &buffer, const InstructionPtr &instruction, const std::string &mnemonic) const
{
    instruction->mnemonic = mnemonic;
    instruction->size = sizeof(u16) * 2;
    instruction->reg(*buffer & 0xF);
    instruction->reg((*buffer++ & 0xF0) >> 4);
    instruction->imm(static_cast<u16>(buffer));
    return true;
}

bool DalvikAssembler::decodeIfOp2(BufferRef &buffer, const InstructionPtr &instruction, const std::string &cond) const
{
    instruction->mnemonic = "if-" + cond;
    instruction->type = InstructionTypes::Jump | InstructionTypes::Conditional;
    instruction->size = sizeof(u16) * 2;
    instruction->reg(*buffer++ & 0xF);
    instruction->imm(instruction->address + (sizeof(u16) * static_cast<s16>(buffer)));
    instruction->targetOp(1);
    return true;
}

bool DalvikAssembler::decodeIfOp3(BufferRef &buffer, const InstructionPtr &instruction, const std::string &cond) const
{
    instruction->mnemonic = "if-" + cond;
    instruction->type = InstructionTypes::Jump | InstructionTypes::Conditional;
    instruction->size = sizeof(u16) * 2;
    instruction->reg(*buffer & 0xF);
    instruction->reg((*buffer++ & 0xF0) >> 4);
    instruction->imm(instruction->address + (sizeof(u16) * static_cast<s16>(buffer)));
    instruction->targetOp(2);
    return true;
}

bool DalvikAssembler::decodeInvoke(BufferRef &buffer, const InstructionPtr &instruction, const std::string &kind) const
{
    u8 firstb = *buffer++;
    u8 argc = firstb >> 4;
    bool needslast = false;

    instruction->size = sizeof(u16) * 2;

    if((argc > 4) && ((argc % 4) == 1))
    {
        needslast = true;
        argc--;
    }

    u16 midx = buffer;

    if(argc)
    {
        buffer.advance(sizeof(u16));
        u16 argwords = std::max(1, argc / 4);
        instruction->size += sizeof(u16) * argwords;

        for(u16 argword = 0, c = 0; (c < argc) && (argword < argwords); argword++)
        {
            u16 word = buffer;

            for(u8 i = 0; (c < argc) && (i < (4 * 8)); i += 4, c++)
            {
                register_t reg = (word & (0xF << i)) >> i;
                u64 regtype = DalvikOperands::Normal;

                if(!c)
                    regtype |= DalvikOperands::ParameterFirst;

                if(!needslast && (c == (argc - 1)))
                    regtype |= DalvikOperands::ParameterLast;

                instruction->reg(reg, regtype);
            }
        }
    }

    if(needslast)
        instruction->reg(firstb & 0xF, DalvikOperands::ParameterLast);

    instruction->imm(midx, DalvikOperands::MethodIndex);
    instruction->type = InstructionTypes::Call;
    instruction->mnemonic = "invoke-" + kind;
    return true;
}

bool DalvikAssembler::decode00(BufferRef &buffer, const InstructionPtr &instruction) const { return this->decodeOp0(buffer, instruction, "nop"); }
bool DalvikAssembler::decode01(BufferRef &buffer, const InstructionPtr &instruction) const { return this->decodeOp2(buffer, instruction, "move"); }
bool DalvikAssembler::decode02(BufferRef &buffer, const InstructionPtr &instruction) const { return this->decodeOp2_16(buffer, instruction, "move/from16"); }

bool DalvikAssembler::decode03(BufferRef &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decode04(BufferRef &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decode05(BufferRef &buffer, const InstructionPtr &instruction) const { return this->decodeOp2_16(buffer, instruction, "move-wide/from16"); }

bool DalvikAssembler::decode06(BufferRef &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decode07(BufferRef &buffer, const InstructionPtr &instruction) const { return this->decodeOp2(buffer, instruction, "move-object"); }
bool DalvikAssembler::decode08(BufferRef &buffer, const InstructionPtr &instruction) const { return this->decodeOp2_16(buffer, instruction, "move-object/from16"); }

bool DalvikAssembler::decode09(BufferRef &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decode0A(BufferRef &buffer, const InstructionPtr &instruction) const { return this->decodeOp1(buffer, instruction, "move-result"); }
bool DalvikAssembler::decode0B(BufferRef &buffer, const InstructionPtr &instruction) const { return this->decodeOp1(buffer, instruction, "move-result-wide");}
bool DalvikAssembler::decode0C(BufferRef &buffer, const InstructionPtr &instruction) const { return this->decodeOp1(buffer, instruction, "move-result-object");}
bool DalvikAssembler::decode0D(BufferRef &buffer, const InstructionPtr &instruction) const { return this->decodeOp1(buffer, instruction, "move-exception"); }
bool DalvikAssembler::decode0E(BufferRef &buffer, const InstructionPtr &instruction) const { return this->decodeOp0(buffer, instruction, "return-void", InstructionTypes::Stop); }
bool DalvikAssembler::decode0F(BufferRef &buffer, const InstructionPtr &instruction) const { return this->decodeOp1(buffer, instruction, "return", InstructionTypes::Stop); }
bool DalvikAssembler::decode10(BufferRef &buffer, const InstructionPtr &instruction) const { return this->decodeOp1(buffer, instruction, "return-wide", InstructionTypes::Stop); }
bool DalvikAssembler::decode11(BufferRef &buffer, const InstructionPtr &instruction) const { return this->decodeOp1(buffer, instruction, "return-object", InstructionTypes::Stop); }

bool DalvikAssembler::decode12(BufferRef &buffer, const InstructionPtr &instruction) const { return this->decodeOp2_imm4(buffer, instruction, "const/4"); }
bool DalvikAssembler::decode13(BufferRef &buffer, const InstructionPtr &instruction) const { return this->decodeOp2_imm16(buffer, instruction, "const/16"); }
bool DalvikAssembler::decode14(BufferRef &buffer, const InstructionPtr &instruction) const { return this->decodeOp2_imm32(buffer, instruction, "const/16"); }

bool DalvikAssembler::decode15(BufferRef &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decode16(BufferRef &buffer, const InstructionPtr &instruction) const { return this->decodeOp2_imm16(buffer, instruction, "const-wide/16"); }
bool DalvikAssembler::decode17(BufferRef &buffer, const InstructionPtr &instruction) const { return this->decodeOp2_imm32(buffer, instruction, "const-wide/32");  }

bool DalvikAssembler::decode18(BufferRef &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decode19(BufferRef &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decode1A(BufferRef &buffer, const InstructionPtr &instruction) const { return this->decodeOp2_s(buffer, instruction, "const-string"); }

bool DalvikAssembler::decode1B(BufferRef &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decode1C(BufferRef &buffer, const InstructionPtr &instruction) const { return this->decodeOp2_t(buffer, instruction, "const-class"); }
bool DalvikAssembler::decode1D(BufferRef &buffer, const InstructionPtr &instruction) const { return this->decodeOp1(buffer, instruction, "monitor-enter"); }
bool DalvikAssembler::decode1E(BufferRef &buffer, const InstructionPtr &instruction) const { return this->decodeOp0(buffer, instruction, "monitor-exit"); }
bool DalvikAssembler::decode1F(BufferRef &buffer, const InstructionPtr &instruction) const { return this->decodeOp2_t(buffer, instruction, "check-cast"); }
bool DalvikAssembler::decode20(BufferRef &buffer, const InstructionPtr &instruction) const { return this->decodeOp3_t(buffer, instruction, "instance-of"); }
bool DalvikAssembler::decode21(BufferRef &buffer, const InstructionPtr &instruction) const { return this->decodeOp2(buffer, instruction, "array-length"); }
bool DalvikAssembler::decode22(BufferRef &buffer, const InstructionPtr &instruction) const { return this->decodeOp2_t(buffer, instruction, "new-instance"); }
bool DalvikAssembler::decode23(BufferRef &buffer, const InstructionPtr &instruction) const { return this->decodeOp3_t(buffer, instruction, "new-array"); }

bool DalvikAssembler::decode24(BufferRef &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decode25(BufferRef &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decode26(BufferRef &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decode27(BufferRef &buffer, const InstructionPtr &instruction) const { return this->decodeOp1(buffer, instruction, "throw-vx"); }

bool DalvikAssembler::decode28(BufferRef &buffer, const InstructionPtr &instruction) const
{
    instruction->mnemonic = "goto";
    instruction->type = InstructionTypes::Jump;
    instruction->size = sizeof(u16);
    instruction->imm(instruction->address + (static_cast<s8>(*buffer) * sizeof(u16)));
    instruction->targetOp(0);
    return true;
}

bool DalvikAssembler::decode29(BufferRef &buffer, const InstructionPtr &instruction) const
{
    instruction->mnemonic = "goto/16";
    instruction->type = InstructionTypes::Jump;
    instruction->size = sizeof(u16) * 2;
    instruction->imm(instruction->address + (static_cast<s16>(buffer) * sizeof(u16)));
    instruction->targetOp(0);
    return true;
}

bool DalvikAssembler::decode2A(BufferRef &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decode2B(BufferRef &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decode2C(BufferRef &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decode2D(BufferRef &buffer, const InstructionPtr &instruction) const { return this->decodeOp3(buffer, instruction, "cmpl-float"); }
bool DalvikAssembler::decode2E(BufferRef &buffer, const InstructionPtr &instruction) const { return this->decodeOp3(buffer, instruction, "cmpg-float"); }
bool DalvikAssembler::decode2F(BufferRef &buffer, const InstructionPtr &instruction) const { return this->decodeOp3(buffer, instruction, "cmpl-double"); }
bool DalvikAssembler::decode30(BufferRef &buffer, const InstructionPtr &instruction) const { return this->decodeOp3(buffer, instruction, "cmpg-double"); }
bool DalvikAssembler::decode31(BufferRef &buffer, const InstructionPtr &instruction) const { return this->decodeOp3(buffer, instruction, "cmp-long"); }
bool DalvikAssembler::decode32(BufferRef &buffer, const InstructionPtr &instruction) const { return this->decodeIfOp3(buffer, instruction, "eq"); }
bool DalvikAssembler::decode33(BufferRef &buffer, const InstructionPtr &instruction) const { return this->decodeIfOp3(buffer, instruction, "ne"); }
bool DalvikAssembler::decode34(BufferRef &buffer, const InstructionPtr &instruction) const { return this->decodeIfOp3(buffer, instruction, "lt"); }
bool DalvikAssembler::decode35(BufferRef &buffer, const InstructionPtr &instruction) const { return this->decodeIfOp3(buffer, instruction, "ge"); }
bool DalvikAssembler::decode36(BufferRef &buffer, const InstructionPtr &instruction) const { return this->decodeIfOp3(buffer, instruction, "gt"); }
bool DalvikAssembler::decode37(BufferRef &buffer, const InstructionPtr &instruction) const { return this->decodeIfOp3(buffer, instruction, "le"); }
bool DalvikAssembler::decode38(BufferRef &buffer, const InstructionPtr &instruction) const { return this->decodeIfOp3(buffer, instruction, "eqz"); }
bool DalvikAssembler::decode39(BufferRef &buffer, const InstructionPtr &instruction) const { return this->decodeIfOp2(buffer, instruction, "nez"); }
bool DalvikAssembler::decode3A(BufferRef &buffer, const InstructionPtr &instruction) const { return this->decodeIfOp2(buffer, instruction, "ltz"); }
bool DalvikAssembler::decode3B(BufferRef &buffer, const InstructionPtr &instruction) const { return this->decodeIfOp2(buffer, instruction, "gez"); }
bool DalvikAssembler::decode3C(BufferRef &buffer, const InstructionPtr &instruction) const { return this->decodeIfOp2(buffer, instruction, "gtz"); }
bool DalvikAssembler::decode3D(BufferRef &buffer, const InstructionPtr &instruction) const { return this->decodeIfOp2(buffer, instruction, "lez"); }

bool DalvikAssembler::decode3E(BufferRef &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decode3F(BufferRef &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decode40(BufferRef &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decode41(BufferRef &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decode42(BufferRef &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decode43(BufferRef &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decode44(BufferRef &buffer, const InstructionPtr &instruction) const { return this->decodeOp3(buffer, instruction, "aget", InstructionTypes::Load); }
bool DalvikAssembler::decode45(BufferRef &buffer, const InstructionPtr &instruction) const { return this->decodeOp3(buffer, instruction, "aget-wide", InstructionTypes::Load); }
bool DalvikAssembler::decode46(BufferRef &buffer, const InstructionPtr &instruction) const { return this->decodeOp3(buffer, instruction, "aget-object", InstructionTypes::Load); }
bool DalvikAssembler::decode47(BufferRef &buffer, const InstructionPtr &instruction) const { return this->decodeOp3(buffer, instruction, "aget-boolean", InstructionTypes::Load); }
bool DalvikAssembler::decode48(BufferRef &buffer, const InstructionPtr &instruction) const { return this->decodeOp3(buffer, instruction, "aget-byte", InstructionTypes::Load); }
bool DalvikAssembler::decode49(BufferRef &buffer, const InstructionPtr &instruction) const { return this->decodeOp3(buffer, instruction, "aget-char", InstructionTypes::Load); }
bool DalvikAssembler::decode4A(BufferRef &buffer, const InstructionPtr &instruction) const { return this->decodeOp3(buffer, instruction, "aget-short", InstructionTypes::Load); }
bool DalvikAssembler::decode4B(BufferRef &buffer, const InstructionPtr &instruction) const { return this->decodeOp3(buffer, instruction, "aput", InstructionTypes::Store); }
bool DalvikAssembler::decode4C(BufferRef &buffer, const InstructionPtr &instruction) const { return this->decodeOp3(buffer, instruction, "aput-wide", InstructionTypes::Store); }
bool DalvikAssembler::decode4D(BufferRef &buffer, const InstructionPtr &instruction) const { return this->decodeOp3(buffer, instruction, "aput-object", InstructionTypes::Store); }
bool DalvikAssembler::decode4E(BufferRef &buffer, const InstructionPtr &instruction) const { return this->decodeOp3(buffer, instruction, "aput-boolean", InstructionTypes::Store); }
bool DalvikAssembler::decode4F(BufferRef &buffer, const InstructionPtr &instruction) const { return this->decodeOp3(buffer, instruction, "aput-byte", InstructionTypes::Store); }
bool DalvikAssembler::decode50(BufferRef &buffer, const InstructionPtr &instruction) const { return this->decodeOp3(buffer, instruction, "aput-char", InstructionTypes::Store); }
bool DalvikAssembler::decode51(BufferRef &buffer, const InstructionPtr &instruction) const { return this->decodeOp3(buffer, instruction, "aput-short", InstructionTypes::Store); }
bool DalvikAssembler::decode52(BufferRef &buffer, const InstructionPtr &instruction) const { return this->decodeOp3_f(buffer, instruction, "iget", InstructionTypes::Load); }
bool DalvikAssembler::decode53(BufferRef &buffer, const InstructionPtr &instruction) const { return this->decodeOp3_f(buffer, instruction, "iget-wide", InstructionTypes::Load); }
bool DalvikAssembler::decode54(BufferRef &buffer, const InstructionPtr &instruction) const { return this->decodeOp3_f(buffer, instruction, "iget-object", InstructionTypes::Load); }
bool DalvikAssembler::decode55(BufferRef &buffer, const InstructionPtr &instruction) const { return this->decodeOp3_f(buffer, instruction, "iget-boolean", InstructionTypes::Load); }
bool DalvikAssembler::decode56(BufferRef &buffer, const InstructionPtr &instruction) const { return this->decodeOp3_f(buffer, instruction, "iget-byte", InstructionTypes::Load); }
bool DalvikAssembler::decode57(BufferRef &buffer, const InstructionPtr &instruction) const { return this->decodeOp3_f(buffer, instruction, "iget-char", InstructionTypes::Load); }
bool DalvikAssembler::decode58(BufferRef &buffer, const InstructionPtr &instruction) const { return this->decodeOp3_f(buffer, instruction, "iget-short", InstructionTypes::Load); }
bool DalvikAssembler::decode59(BufferRef &buffer, const InstructionPtr &instruction) const { return this->decodeOp3_f(buffer, instruction, "iput", InstructionTypes::Store); }
bool DalvikAssembler::decode5A(BufferRef &buffer, const InstructionPtr &instruction) const { return this->decodeOp3_f(buffer, instruction, "iput-wide", InstructionTypes::Store); }
bool DalvikAssembler::decode5B(BufferRef &buffer, const InstructionPtr &instruction) const { return this->decodeOp3_f(buffer, instruction, "iput-object", InstructionTypes::Store); }
bool DalvikAssembler::decode5C(BufferRef &buffer, const InstructionPtr &instruction) const { return this->decodeOp3_f(buffer, instruction, "iput-boolean", InstructionTypes::Store); }
bool DalvikAssembler::decode5D(BufferRef &buffer, const InstructionPtr &instruction) const { return this->decodeOp3_f(buffer, instruction, "iput-byte", InstructionTypes::Store); }
bool DalvikAssembler::decode5E(BufferRef &buffer, const InstructionPtr &instruction) const { return this->decodeOp3_f(buffer, instruction, "iput-char", InstructionTypes::Store); }
bool DalvikAssembler::decode5F(BufferRef &buffer, const InstructionPtr &instruction) const { return this->decodeOp3_f(buffer, instruction, "iput-short", InstructionTypes::Store); }
bool DalvikAssembler::decode60(BufferRef &buffer, const InstructionPtr &instruction) const { return this->decodeOp2_f(buffer, instruction, "sget", InstructionTypes::Load); }
bool DalvikAssembler::decode61(BufferRef &buffer, const InstructionPtr &instruction) const { return this->decodeOp2_f(buffer, instruction, "sget-wide", InstructionTypes::Load); }
bool DalvikAssembler::decode62(BufferRef &buffer, const InstructionPtr &instruction) const { return this->decodeOp2_f(buffer, instruction, "sget-object", InstructionTypes::Load); }
bool DalvikAssembler::decode63(BufferRef &buffer, const InstructionPtr &instruction) const { return this->decodeOp2_f(buffer, instruction, "sget-boolean", InstructionTypes::Load); }
bool DalvikAssembler::decode64(BufferRef &buffer, const InstructionPtr &instruction) const { return this->decodeOp2_f(buffer, instruction, "sget-byte", InstructionTypes::Load); }
bool DalvikAssembler::decode65(BufferRef &buffer, const InstructionPtr &instruction) const { return this->decodeOp2_f(buffer, instruction, "sget-char", InstructionTypes::Load); }
bool DalvikAssembler::decode66(BufferRef &buffer, const InstructionPtr &instruction) const { return this->decodeOp2_f(buffer, instruction, "sget-short", InstructionTypes::Load); }
bool DalvikAssembler::decode67(BufferRef &buffer, const InstructionPtr &instruction) const { return this->decodeOp2_f(buffer, instruction, "sput", InstructionTypes::Store); }
bool DalvikAssembler::decode68(BufferRef &buffer, const InstructionPtr &instruction) const { return this->decodeOp2_f(buffer, instruction, "sput-wide", InstructionTypes::Store); }
bool DalvikAssembler::decode69(BufferRef &buffer, const InstructionPtr &instruction) const { return this->decodeOp2_f(buffer, instruction, "sput-object", InstructionTypes::Store); }
bool DalvikAssembler::decode6A(BufferRef &buffer, const InstructionPtr &instruction) const { return this->decodeOp2_f(buffer, instruction, "sput-boolean", InstructionTypes::Store); }
bool DalvikAssembler::decode6B(BufferRef &buffer, const InstructionPtr &instruction) const { return this->decodeOp2_f(buffer, instruction, "sput-byte", InstructionTypes::Store); }
bool DalvikAssembler::decode6C(BufferRef &buffer, const InstructionPtr &instruction) const { return this->decodeOp2_f(buffer, instruction, "sput-char", InstructionTypes::Store); }
bool DalvikAssembler::decode6D(BufferRef &buffer, const InstructionPtr &instruction) const { return this->decodeOp2_f(buffer, instruction, "sput-short", InstructionTypes::Store); }
bool DalvikAssembler::decode6E(BufferRef &buffer, const InstructionPtr &instruction) const { return this->decodeInvoke(buffer, instruction, "virtual"); }
bool DalvikAssembler::decode6F(BufferRef &buffer, const InstructionPtr &instruction) const { return this->decodeInvoke(buffer, instruction, "super"); }
bool DalvikAssembler::decode70(BufferRef &buffer, const InstructionPtr &instruction) const { return this->decodeInvoke(buffer, instruction, "direct"); }
bool DalvikAssembler::decode71(BufferRef &buffer, const InstructionPtr &instruction) const { return this->decodeInvoke(buffer, instruction, "static"); }
bool DalvikAssembler::decode72(BufferRef &buffer, const InstructionPtr &instruction) const { return this->decodeInvoke(buffer, instruction, "interface"); }

bool DalvikAssembler::decode73(BufferRef &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decode74(BufferRef &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decode75(BufferRef &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decode76(BufferRef &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decode77(BufferRef &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decode78(BufferRef &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decode79(BufferRef &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decode7A(BufferRef &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decode7B(BufferRef &buffer, const InstructionPtr &instruction) const { return this->decodeOp2(buffer, instruction, "neg-int"); }

bool DalvikAssembler::decode7C(BufferRef &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decode7D(BufferRef &buffer, const InstructionPtr &instruction) const { return this->decodeOp2(buffer, instruction, "neg-long"); }

bool DalvikAssembler::decode7E(BufferRef &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decode7F(BufferRef &buffer, const InstructionPtr &instruction) const { return this->decodeOp2(buffer, instruction, "neg-float"); }
bool DalvikAssembler::decode80(BufferRef &buffer, const InstructionPtr &instruction) const { return this->decodeOp2(buffer, instruction, "neg-double"); }
bool DalvikAssembler::decode81(BufferRef &buffer, const InstructionPtr &instruction) const { return this->decodeOp2(buffer, instruction, "int-to-long"); }
bool DalvikAssembler::decode82(BufferRef &buffer, const InstructionPtr &instruction) const { return this->decodeOp2(buffer, instruction, "int-to-float"); }
bool DalvikAssembler::decode83(BufferRef &buffer, const InstructionPtr &instruction) const { return this->decodeOp2(buffer, instruction, "int-to-double"); }
bool DalvikAssembler::decode84(BufferRef &buffer, const InstructionPtr &instruction) const { return this->decodeOp2(buffer, instruction, "long-to-int"); }
bool DalvikAssembler::decode85(BufferRef &buffer, const InstructionPtr &instruction) const { return this->decodeOp2(buffer, instruction, "long-to-float"); }
bool DalvikAssembler::decode86(BufferRef &buffer, const InstructionPtr &instruction) const { return this->decodeOp2(buffer, instruction, "long-to-double"); }
bool DalvikAssembler::decode87(BufferRef &buffer, const InstructionPtr &instruction) const { return this->decodeOp2(buffer, instruction, "float-to-int"); }
bool DalvikAssembler::decode88(BufferRef &buffer, const InstructionPtr &instruction) const { return this->decodeOp2(buffer, instruction, "float-to-long"); }
bool DalvikAssembler::decode89(BufferRef &buffer, const InstructionPtr &instruction) const { return this->decodeOp2(buffer, instruction, "float-to-double"); }
bool DalvikAssembler::decode8A(BufferRef &buffer, const InstructionPtr &instruction) const { return this->decodeOp2(buffer, instruction, "double-to-int"); }
bool DalvikAssembler::decode8B(BufferRef &buffer, const InstructionPtr &instruction) const { return this->decodeOp2(buffer, instruction, "double-to-long"); }
bool DalvikAssembler::decode8C(BufferRef &buffer, const InstructionPtr &instruction) const { return this->decodeOp2(buffer, instruction, "double-to-float"); }
bool DalvikAssembler::decode8D(BufferRef &buffer, const InstructionPtr &instruction) const { return this->decodeOp2(buffer, instruction, "int-to-byte"); }
bool DalvikAssembler::decode8E(BufferRef &buffer, const InstructionPtr &instruction) const { return this->decodeOp2(buffer, instruction, "int-to-char"); }
bool DalvikAssembler::decode8F(BufferRef &buffer, const InstructionPtr &instruction) const { return this->decodeOp2(buffer, instruction, "int-to-short"); }
bool DalvikAssembler::decode90(BufferRef &buffer, const InstructionPtr &instruction) const { return this->decodeOp3(buffer, instruction, "add-int"); }
bool DalvikAssembler::decode91(BufferRef &buffer, const InstructionPtr &instruction) const { return this->decodeOp3(buffer, instruction, "sub-int"); }
bool DalvikAssembler::decode92(BufferRef &buffer, const InstructionPtr &instruction) const { return this->decodeOp3(buffer, instruction, "mul-int"); }
bool DalvikAssembler::decode93(BufferRef &buffer, const InstructionPtr &instruction) const { return this->decodeOp3(buffer, instruction, "div-int"); }
bool DalvikAssembler::decode94(BufferRef &buffer, const InstructionPtr &instruction) const { return this->decodeOp3(buffer, instruction, "rem-int"); }
bool DalvikAssembler::decode95(BufferRef &buffer, const InstructionPtr &instruction) const { return this->decodeOp3(buffer, instruction, "and-int"); }
bool DalvikAssembler::decode96(BufferRef &buffer, const InstructionPtr &instruction) const { return this->decodeOp3(buffer, instruction, "or-int"); }
bool DalvikAssembler::decode97(BufferRef &buffer, const InstructionPtr &instruction) const { return this->decodeOp3(buffer, instruction, "xor-int"); }
bool DalvikAssembler::decode98(BufferRef &buffer, const InstructionPtr &instruction) const { return this->decodeOp3(buffer, instruction, "shl-int"); }
bool DalvikAssembler::decode99(BufferRef &buffer, const InstructionPtr &instruction) const { return this->decodeOp3(buffer, instruction, "shr-int"); }
bool DalvikAssembler::decode9A(BufferRef &buffer, const InstructionPtr &instruction) const { return this->decodeOp3(buffer, instruction, "ushr-int"); }
bool DalvikAssembler::decode9B(BufferRef &buffer, const InstructionPtr &instruction) const { return this->decodeOp3(buffer, instruction, "add-long"); }
bool DalvikAssembler::decode9C(BufferRef &buffer, const InstructionPtr &instruction) const { return this->decodeOp3(buffer, instruction, "sub-long"); }
bool DalvikAssembler::decode9D(BufferRef &buffer, const InstructionPtr &instruction) const { return this->decodeOp3(buffer, instruction, "mul-long"); }
bool DalvikAssembler::decode9E(BufferRef &buffer, const InstructionPtr &instruction) const { return this->decodeOp3(buffer, instruction, "div-long"); }
bool DalvikAssembler::decode9F(BufferRef &buffer, const InstructionPtr &instruction) const { return this->decodeOp3(buffer, instruction, "rem-long"); }
bool DalvikAssembler::decodeA0(BufferRef &buffer, const InstructionPtr &instruction) const { return this->decodeOp3(buffer, instruction, "and-long"); }
bool DalvikAssembler::decodeA1(BufferRef &buffer, const InstructionPtr &instruction) const { return this->decodeOp3(buffer, instruction, "or-long"); }
bool DalvikAssembler::decodeA2(BufferRef &buffer, const InstructionPtr &instruction) const { return this->decodeOp3(buffer, instruction, "xor-long"); }
bool DalvikAssembler::decodeA3(BufferRef &buffer, const InstructionPtr &instruction) const { return this->decodeOp3(buffer, instruction, "shl-long"); }
bool DalvikAssembler::decodeA4(BufferRef &buffer, const InstructionPtr &instruction) const { return this->decodeOp3(buffer, instruction, "shr-long"); }
bool DalvikAssembler::decodeA5(BufferRef &buffer, const InstructionPtr &instruction) const { return this->decodeOp3(buffer, instruction, "ushr-long"); }
bool DalvikAssembler::decodeA6(BufferRef &buffer, const InstructionPtr &instruction) const { return this->decodeOp3(buffer, instruction, "add-float"); }
bool DalvikAssembler::decodeA7(BufferRef &buffer, const InstructionPtr &instruction) const { return this->decodeOp3(buffer, instruction, "sub-float"); }
bool DalvikAssembler::decodeA8(BufferRef &buffer, const InstructionPtr &instruction) const { return this->decodeOp3(buffer, instruction, "mul-float"); }
bool DalvikAssembler::decodeA9(BufferRef &buffer, const InstructionPtr &instruction) const { return this->decodeOp3(buffer, instruction, "div-float"); }
bool DalvikAssembler::decodeAA(BufferRef &buffer, const InstructionPtr &instruction) const { return this->decodeOp3(buffer, instruction, "rem-float"); }
bool DalvikAssembler::decodeAB(BufferRef &buffer, const InstructionPtr &instruction) const { return this->decodeOp3(buffer, instruction, "add-double"); }
bool DalvikAssembler::decodeAC(BufferRef &buffer, const InstructionPtr &instruction) const { return this->decodeOp3(buffer, instruction, "sub-double"); }
bool DalvikAssembler::decodeAD(BufferRef &buffer, const InstructionPtr &instruction) const { return this->decodeOp3(buffer, instruction, "mul-double"); }
bool DalvikAssembler::decodeAE(BufferRef &buffer, const InstructionPtr &instruction) const { return this->decodeOp3(buffer, instruction, "div-double"); }
bool DalvikAssembler::decodeAF(BufferRef &buffer, const InstructionPtr &instruction) const { return this->decodeOp3(buffer, instruction, "rem-double"); }
bool DalvikAssembler::decodeB0(BufferRef &buffer, const InstructionPtr &instruction) const { return this->decodeOp2(buffer, instruction, "add-int/2addr"); }
bool DalvikAssembler::decodeB1(BufferRef &buffer, const InstructionPtr &instruction) const { return this->decodeOp2(buffer, instruction, "sub-int/2addr"); }
bool DalvikAssembler::decodeB2(BufferRef &buffer, const InstructionPtr &instruction) const { return this->decodeOp2(buffer, instruction, "mul-int/2addr"); }
bool DalvikAssembler::decodeB3(BufferRef &buffer, const InstructionPtr &instruction) const { return this->decodeOp2(buffer, instruction, "div-int/2addr"); }
bool DalvikAssembler::decodeB4(BufferRef &buffer, const InstructionPtr &instruction) const { return this->decodeOp2(buffer, instruction, "rem-int/2addr"); }
bool DalvikAssembler::decodeB5(BufferRef &buffer, const InstructionPtr &instruction) const { return this->decodeOp2(buffer, instruction, "and-int/2addr"); }
bool DalvikAssembler::decodeB6(BufferRef &buffer, const InstructionPtr &instruction) const { return this->decodeOp2(buffer, instruction, "or-int/2addr"); }
bool DalvikAssembler::decodeB7(BufferRef &buffer, const InstructionPtr &instruction) const { return this->decodeOp2(buffer, instruction, "xor-int/2addr"); }
bool DalvikAssembler::decodeB8(BufferRef &buffer, const InstructionPtr &instruction) const { return this->decodeOp2(buffer, instruction, "shl-int/2addr"); }
bool DalvikAssembler::decodeB9(BufferRef &buffer, const InstructionPtr &instruction) const { return this->decodeOp2(buffer, instruction, "shr-int/2addr"); }
bool DalvikAssembler::decodeBA(BufferRef &buffer, const InstructionPtr &instruction) const { return this->decodeOp2(buffer, instruction, "ushr-int/2addr"); }
bool DalvikAssembler::decodeBB(BufferRef &buffer, const InstructionPtr &instruction) const { return this->decodeOp2(buffer, instruction, "add-long/2addr"); }
bool DalvikAssembler::decodeBC(BufferRef &buffer, const InstructionPtr &instruction) const { return this->decodeOp2(buffer, instruction, "sub-long/2addr"); }
bool DalvikAssembler::decodeBD(BufferRef &buffer, const InstructionPtr &instruction) const { return this->decodeOp2(buffer, instruction, "mul-long/2addr"); }
bool DalvikAssembler::decodeBE(BufferRef &buffer, const InstructionPtr &instruction) const { return this->decodeOp2(buffer, instruction, "div-long/2addr"); }
bool DalvikAssembler::decodeBF(BufferRef &buffer, const InstructionPtr &instruction) const { return this->decodeOp2(buffer, instruction, "rem-long/2addr"); }
bool DalvikAssembler::decodeC0(BufferRef &buffer, const InstructionPtr &instruction) const { return this->decodeOp2(buffer, instruction, "and-long/2addr"); }
bool DalvikAssembler::decodeC1(BufferRef &buffer, const InstructionPtr &instruction) const { return this->decodeOp2(buffer, instruction, "or-long/2addr"); }
bool DalvikAssembler::decodeC2(BufferRef &buffer, const InstructionPtr &instruction) const { return this->decodeOp2(buffer, instruction, "xor-long/2addr"); }
bool DalvikAssembler::decodeC3(BufferRef &buffer, const InstructionPtr &instruction) const { return this->decodeOp2(buffer, instruction, "shl-long/2addr"); }
bool DalvikAssembler::decodeC4(BufferRef &buffer, const InstructionPtr &instruction) const { return this->decodeOp2(buffer, instruction, "shr-long/2addr"); }
bool DalvikAssembler::decodeC5(BufferRef &buffer, const InstructionPtr &instruction) const { return this->decodeOp2(buffer, instruction, "ushr-long/2addr"); }
bool DalvikAssembler::decodeC6(BufferRef &buffer, const InstructionPtr &instruction) const { return this->decodeOp2(buffer, instruction, "add-float/2addr"); }
bool DalvikAssembler::decodeC7(BufferRef &buffer, const InstructionPtr &instruction) const { return this->decodeOp2(buffer, instruction, "sub-float/2addr"); }
bool DalvikAssembler::decodeC8(BufferRef &buffer, const InstructionPtr &instruction) const { return this->decodeOp2(buffer, instruction, "mul-float/2addr"); }
bool DalvikAssembler::decodeC9(BufferRef &buffer, const InstructionPtr &instruction) const { return this->decodeOp2(buffer, instruction, "div-float/2addr"); }
bool DalvikAssembler::decodeCA(BufferRef &buffer, const InstructionPtr &instruction) const { return this->decodeOp2(buffer, instruction, "rem-float/2addr"); }
bool DalvikAssembler::decodeCB(BufferRef &buffer, const InstructionPtr &instruction) const { return this->decodeOp2(buffer, instruction, "add-double/2addr"); }
bool DalvikAssembler::decodeCC(BufferRef &buffer, const InstructionPtr &instruction) const { return this->decodeOp2(buffer, instruction, "sub-double/2addr"); }
bool DalvikAssembler::decodeCD(BufferRef &buffer, const InstructionPtr &instruction) const { return this->decodeOp2(buffer, instruction, "mul-double/2addr"); }
bool DalvikAssembler::decodeCE(BufferRef &buffer, const InstructionPtr &instruction) const { return this->decodeOp2(buffer, instruction, "div-double/2addr"); }
bool DalvikAssembler::decodeCF(BufferRef &buffer, const InstructionPtr &instruction) const { return this->decodeOp2(buffer, instruction, "rem-double/2addr"); }
bool DalvikAssembler::decodeD0(BufferRef &buffer, const InstructionPtr &instruction) const { return this->decodeOp3_imm16(buffer, instruction, "add-int/lit16"); }
bool DalvikAssembler::decodeD1(BufferRef &buffer, const InstructionPtr &instruction) const { return this->decodeOp3_imm16(buffer, instruction, "sub-int/lit16"); }
bool DalvikAssembler::decodeD2(BufferRef &buffer, const InstructionPtr &instruction) const { return this->decodeOp3_imm16(buffer, instruction, "mul-int/lit16"); }
bool DalvikAssembler::decodeD3(BufferRef &buffer, const InstructionPtr &instruction) const { return this->decodeOp3_imm16(buffer, instruction, "div-int/lit16"); }
bool DalvikAssembler::decodeD4(BufferRef &buffer, const InstructionPtr &instruction) const { return this->decodeOp3_imm16(buffer, instruction, "rem-int/lit16"); }
bool DalvikAssembler::decodeD5(BufferRef &buffer, const InstructionPtr &instruction) const { return this->decodeOp3_imm16(buffer, instruction, "and-int/lit16"); }
bool DalvikAssembler::decodeD6(BufferRef &buffer, const InstructionPtr &instruction) const { return this->decodeOp3_imm16(buffer, instruction, "or-int/lit16"); }
bool DalvikAssembler::decodeD7(BufferRef &buffer, const InstructionPtr &instruction) const { return this->decodeOp3_imm16(buffer, instruction, "xor-int/lit16"); }
bool DalvikAssembler::decodeD8(BufferRef &buffer, const InstructionPtr &instruction) const { return this->decodeOp3_imm8(buffer, instruction, "add-int/lit8"); }
bool DalvikAssembler::decodeD9(BufferRef &buffer, const InstructionPtr &instruction) const { return this->decodeOp3_imm8(buffer, instruction, "sub-int/lit8"); }
bool DalvikAssembler::decodeDA(BufferRef &buffer, const InstructionPtr &instruction) const { return this->decodeOp3_imm8(buffer, instruction, "mul-int/lit8"); }
bool DalvikAssembler::decodeDB(BufferRef &buffer, const InstructionPtr &instruction) const { return this->decodeOp3_imm8(buffer, instruction, "div-int/lit8"); }
bool DalvikAssembler::decodeDC(BufferRef &buffer, const InstructionPtr &instruction) const { return this->decodeOp3_imm8(buffer, instruction, "rem-int/lit8"); }
bool DalvikAssembler::decodeDD(BufferRef &buffer, const InstructionPtr &instruction) const { return this->decodeOp3_imm8(buffer, instruction, "and-int/lit8"); }
bool DalvikAssembler::decodeDE(BufferRef &buffer, const InstructionPtr &instruction) const { return this->decodeOp3_imm8(buffer, instruction, "or-int/lit8"); }
bool DalvikAssembler::decodeDF(BufferRef &buffer, const InstructionPtr &instruction) const { return this->decodeOp3_imm8(buffer, instruction, "xor-int/lit8"); }
bool DalvikAssembler::decodeE0(BufferRef &buffer, const InstructionPtr &instruction) const { return this->decodeOp3_imm8(buffer, instruction, "shl-int/lit8"); }
bool DalvikAssembler::decodeE1(BufferRef &buffer, const InstructionPtr &instruction) const { return this->decodeOp3_imm8(buffer, instruction, "shr-int/lit8"); }
bool DalvikAssembler::decodeE2(BufferRef &buffer, const InstructionPtr &instruction) const { return this->decodeOp3_imm8(buffer, instruction, "ushr-int/lit8"); }

bool DalvikAssembler::decodeE3(BufferRef &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decodeE4(BufferRef &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decodeE5(BufferRef &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decodeE6(BufferRef &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decodeE7(BufferRef &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decodeE8(BufferRef &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decodeE9(BufferRef &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decodeEA(BufferRef &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decodeEB(BufferRef &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decodeEC(BufferRef &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decodeED(BufferRef &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decodeEE(BufferRef &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decodeEF(BufferRef &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decodeF0(BufferRef &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decodeF1(BufferRef &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decodeF2(BufferRef &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decodeF3(BufferRef &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decodeF4(BufferRef &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decodeF5(BufferRef &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decodeF6(BufferRef &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decodeF7(BufferRef &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decodeF8(BufferRef &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decodeF9(BufferRef &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decodeFA(BufferRef &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decodeFB(BufferRef &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decodeFC(BufferRef &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decodeFD(BufferRef &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decodeFE(BufferRef &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decodeFF(BufferRef &buffer, const InstructionPtr &instruction) const
{
    return false;
}

} // namespace REDasm
