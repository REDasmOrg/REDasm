#include "dalvik.h"
#include "../../formats/dex/dex.h"
#include "dalvik_printer.h"
#include "dalvik_opcodes.h"
#include "dalvik_metadata.h"

#define SET_DECODE_OPCODE_TO(opcode) _opcodemap[0x##opcode] = [this](Buffer& buffer, const InstructionPtr& instruction) -> bool { return decode##opcode(buffer, instruction); }

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

const char *DalvikAssembler::name() const
{
    return "Dalvik VM";
}

Printer *DalvikAssembler::createPrinter(DisassemblerFunctions *disassembler, SymbolTable *symboltable) const
{
    return new DalvikPrinter(disassembler, symboltable);
}

void DalvikAssembler::analyzeOperand(DisassemblerFunctions *disassembler, const InstructionPtr &instruction, const Operand &operand) const
{
    AssemblerPlugin::analyzeOperand(disassembler, instruction, operand);

    DEXFormat* dexformat = dynamic_cast<DEXFormat*>(disassembler->format());

    if(!dexformat)
        return;

    if(operand.extra_type == DalvikOperands::StringIndex)
    {
        offset_t offset = 0;

        if(!dexformat->getStringOffset(operand.u_value, offset))
            return;

        SymbolTable* symboltable = disassembler->symbolTable();
        symboltable->createString(offset);
        disassembler->pushReference(symboltable->symbol(offset), instruction->address);
    }
}

bool DalvikAssembler::decode(Buffer buffer, const InstructionPtr &instruction)
{
    instruction->id = *buffer;

    auto it = this->_opcodemap.find(instruction->id);

    if(it == this->_opcodemap.end())
        return false;

    buffer++; // Skip opcode
    bool res = it->second(buffer, instruction);

    if(!res)
        instruction->size = sizeof(u16); // Dalvik uses always 16-bit aligned instructions

    AssemblerPlugin::decode(buffer, instruction);
    return res;
}

bool DalvikAssembler::decodeOp0(Buffer &buffer, const InstructionPtr &instruction, const std::string &mnemonic, u32 type) const
{
    RE_UNUSED(buffer);
    instruction->mnemonic = mnemonic;
    instruction->type = type;
    instruction->size = sizeof(u16);
    return true;
}

bool DalvikAssembler::decodeOp1(Buffer &buffer, const InstructionPtr &instruction, const std::string &mnemonic, u32 type) const
{
    instruction->mnemonic = mnemonic;
    instruction->type = type;
    instruction->size = sizeof(u16);
    instruction->reg(*buffer & 0xF);
    return true;
}

bool DalvikAssembler::decodeOp2(Buffer &buffer, const InstructionPtr &instruction, const std::string &mnemonic) const
{
    instruction->mnemonic = mnemonic;
    instruction->size = sizeof(u16);
    instruction->reg(*buffer & 0xF);
    instruction->reg((*buffer & 0xF0) >> 4);
    return true;
}

bool DalvikAssembler::decodeOp3(Buffer &buffer, const InstructionPtr &instruction, const std::string &mnemonic, u32 type) const
{
    instruction->mnemonic = mnemonic;
    instruction->type = type;
    instruction->size = sizeof(u16) * 2;
    instruction->reg(*buffer++);
    instruction->reg(*buffer++);
    instruction->reg(*buffer);
    return true;
}

bool DalvikAssembler::decodeOp2_s(Buffer &buffer, const InstructionPtr &instruction, const std::string &mnemonic) const
{
    instruction->mnemonic = mnemonic;
    instruction->size = sizeof(u16) * 2;
    instruction->reg(*buffer++);
    instruction->imm(this->read<u16>(buffer), DalvikOperands::StringIndex);
    return true;
}

bool DalvikAssembler::decodeOp2_t(Buffer &buffer, const InstructionPtr &instruction, const std::string &mnemonic) const
{
    instruction->mnemonic = mnemonic;
    instruction->size = sizeof(u16) * 2;
    instruction->reg(*buffer++);
    instruction->imm(this->read<u16>(buffer), DalvikOperands::TypeIndex);
    return true;
}

bool DalvikAssembler::decodeOp2_f(Buffer &buffer, const InstructionPtr &instruction, const std::string &mnemonic, u32 type) const
{
    instruction->mnemonic = mnemonic;
    instruction->type = type;
    instruction->size = sizeof(u16) * 2;
    instruction->reg(*buffer++);
    instruction->imm(this->read<u16>(buffer), DalvikOperands::FieldIndex);
    return true;
}

bool DalvikAssembler::decodeOp2_16(Buffer &buffer, const InstructionPtr &instruction, const std::string &mnemonic) const
{
    instruction->mnemonic = mnemonic;
    instruction->size = sizeof(u16) * 2;
    instruction->reg(*buffer++);
    instruction->reg(this->read<u16>(buffer));
    return true;
}

bool DalvikAssembler::decodeOp2_imm4(Buffer &buffer, const InstructionPtr &instruction, const std::string &mnemonic) const
{
    instruction->mnemonic = mnemonic;
    instruction->size = sizeof(u16);
    instruction->reg(*buffer & 0xF);
    instruction->imm((*buffer & 0xF0) >> 4);
    return true;
}

bool DalvikAssembler::decodeOp2_imm16(Buffer &buffer, const InstructionPtr &instruction, const std::string &mnemonic) const
{
    instruction->mnemonic = mnemonic;
    instruction->size = sizeof(u16) * 2;
    instruction->reg(*buffer++);
    instruction->imm(this->read<u16>(buffer));
    return true;
}

bool DalvikAssembler::decodeOp2_imm32(Buffer &buffer, const InstructionPtr &instruction, const std::string &mnemonic) const
{
    instruction->mnemonic = mnemonic;
    instruction->size = sizeof(u16) * 3;
    instruction->reg(*buffer++);
    instruction->imm(this->read<u32>(buffer));
    return true;
}

bool DalvikAssembler::decodeOp3_f(Buffer &buffer, const InstructionPtr &instruction, const std::string &mnemonic, u32 type) const
{
    instruction->mnemonic = mnemonic;
    instruction->type = type;
    instruction->size = sizeof(u16) * 2;
    instruction->reg(*buffer & 0xF);
    instruction->reg((*buffer++ & 0xF0) >> 4);
    instruction->imm(this->read<u16>(buffer), DalvikOperands::FieldIndex);
    return true;
}

bool DalvikAssembler::decodeOp3_t(Buffer &buffer, const InstructionPtr &instruction, const std::string &mnemonic, u32 type) const
{
    instruction->mnemonic = mnemonic;
    instruction->type = type;
    instruction->size = sizeof(u16) * 2;
    instruction->reg(*buffer & 0xF);
    instruction->reg((*buffer++ & 0xF0) >> 4);
    instruction->imm(this->read<u16>(buffer), DalvikOperands::TypeIndex);
    return true;
}

bool DalvikAssembler::decodeIfOp2(Buffer &buffer, const InstructionPtr &instruction, const std::string &cond) const
{
    instruction->mnemonic = "if-" + cond;
    instruction->type = InstructionTypes::Jump | InstructionTypes::Conditional;
    instruction->size = sizeof(u16) * 2;
    instruction->reg(*buffer++ & 0xF);
    instruction->imm(instruction->address + (sizeof(u16) * this->read<s16>(buffer)));
    instruction->target_op(1);
    return true;
}

bool DalvikAssembler::decodeIfOp3(Buffer &buffer, const InstructionPtr &instruction, const std::string &cond) const
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

bool DalvikAssembler::decodeInvoke(Buffer &buffer, const InstructionPtr &instruction, const std::string &kind) const
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

    u16 midx = this->read<u16>(buffer);

    if(argc)
    {
        buffer += sizeof(u16);
        u16 argwords = std::max(1, argc / 4);
        instruction->size += sizeof(u16) * argwords;

        for(u16 argword = 0, c = 0; (c < argc) && (argword < argwords); argword++)
        {
            u16 word = this->read<u16>(buffer);

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

bool DalvikAssembler::decode00(Buffer &buffer, const InstructionPtr &instruction) const { return this->decodeOp0(buffer, instruction, "nop"); }
bool DalvikAssembler::decode01(Buffer &buffer, const InstructionPtr &instruction) const { return this->decodeOp2(buffer, instruction, "move"); }
bool DalvikAssembler::decode02(Buffer &buffer, const InstructionPtr &instruction) const { return this->decodeOp2_16(buffer, instruction, "move/from16"); }

bool DalvikAssembler::decode03(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decode04(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decode05(Buffer &buffer, const InstructionPtr &instruction) const { return this->decodeOp2_16(buffer, instruction, "move-wide/from16"); }

bool DalvikAssembler::decode06(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decode07(Buffer &buffer, const InstructionPtr &instruction) const { return this->decodeOp2(buffer, instruction, "move-object"); }
bool DalvikAssembler::decode08(Buffer &buffer, const InstructionPtr &instruction) const { return this->decodeOp2_16(buffer, instruction, "move-object/from16"); }

bool DalvikAssembler::decode09(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decode0A(Buffer &buffer, const InstructionPtr &instruction) const { return this->decodeOp1(buffer, instruction, "move-result"); }
bool DalvikAssembler::decode0B(Buffer &buffer, const InstructionPtr &instruction) const { return this->decodeOp1(buffer, instruction, "move-result-wide");}
bool DalvikAssembler::decode0C(Buffer &buffer, const InstructionPtr &instruction) const { return this->decodeOp1(buffer, instruction, "move-result-object");}
bool DalvikAssembler::decode0D(Buffer &buffer, const InstructionPtr &instruction) const { return this->decodeOp1(buffer, instruction, "move-exception"); }
bool DalvikAssembler::decode0E(Buffer &buffer, const InstructionPtr &instruction) const { return this->decodeOp0(buffer, instruction, "return-void", InstructionTypes::Stop); }
bool DalvikAssembler::decode0F(Buffer &buffer, const InstructionPtr &instruction) const { return this->decodeOp1(buffer, instruction, "return", InstructionTypes::Stop); }
bool DalvikAssembler::decode10(Buffer &buffer, const InstructionPtr &instruction) const { return this->decodeOp1(buffer, instruction, "return-wide", InstructionTypes::Stop); }
bool DalvikAssembler::decode11(Buffer &buffer, const InstructionPtr &instruction) const { return this->decodeOp1(buffer, instruction, "return-object", InstructionTypes::Stop); }

bool DalvikAssembler::decode12(Buffer &buffer, const InstructionPtr &instruction) const { return this->decodeOp2_imm4(buffer, instruction, "const/4"); }
bool DalvikAssembler::decode13(Buffer &buffer, const InstructionPtr &instruction) const { return this->decodeOp2_imm16(buffer, instruction, "const/16"); }
bool DalvikAssembler::decode14(Buffer &buffer, const InstructionPtr &instruction) const { return this->decodeOp2_imm32(buffer, instruction, "const/16"); }

bool DalvikAssembler::decode15(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decode16(Buffer &buffer, const InstructionPtr &instruction) const { return this->decodeOp2_imm16(buffer, instruction, "const-wide/16"); }
bool DalvikAssembler::decode17(Buffer &buffer, const InstructionPtr &instruction) const { return this->decodeOp2_imm32(buffer, instruction, "const-wide/32");  }

bool DalvikAssembler::decode18(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decode19(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decode1A(Buffer &buffer, const InstructionPtr &instruction) const { return this->decodeOp2_s(buffer, instruction, "const-string"); }

bool DalvikAssembler::decode1B(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decode1C(Buffer &buffer, const InstructionPtr &instruction) const { return this->decodeOp2_t(buffer, instruction, "const-class"); }
bool DalvikAssembler::decode1D(Buffer &buffer, const InstructionPtr &instruction) const { return this->decodeOp1(buffer, instruction, "monitor-enter"); }
bool DalvikAssembler::decode1E(Buffer &buffer, const InstructionPtr &instruction) const { return this->decodeOp0(buffer, instruction, "monitor-exit"); }
bool DalvikAssembler::decode1F(Buffer &buffer, const InstructionPtr &instruction) const { return this->decodeOp2_t(buffer, instruction, "check-cast"); }
bool DalvikAssembler::decode20(Buffer &buffer, const InstructionPtr &instruction) const { return this->decodeOp3_t(buffer, instruction, "instance-of"); }
bool DalvikAssembler::decode21(Buffer &buffer, const InstructionPtr &instruction) const { return this->decodeOp2(buffer, instruction, "array-length"); }
bool DalvikAssembler::decode22(Buffer &buffer, const InstructionPtr &instruction) const { return this->decodeOp2_t(buffer, instruction, "new-instance"); }
bool DalvikAssembler::decode23(Buffer &buffer, const InstructionPtr &instruction) const { return this->decodeOp3_t(buffer, instruction, "new-array"); }

bool DalvikAssembler::decode24(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decode25(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decode26(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decode27(Buffer &buffer, const InstructionPtr &instruction) const { return this->decodeOp1(buffer, instruction, "throw-vx"); }

bool DalvikAssembler::decode28(Buffer &buffer, const InstructionPtr &instruction) const
{
    instruction->mnemonic = "goto";
    instruction->type = InstructionTypes::Jump;
    instruction->size = sizeof(u16);
    instruction->imm(instruction->address + (static_cast<s8>(*buffer) * sizeof(u16)));
    instruction->target_op(0);
    return true;
}

bool DalvikAssembler::decode29(Buffer &buffer, const InstructionPtr &instruction) const
{
    instruction->mnemonic = "goto/16";
    instruction->type = InstructionTypes::Jump;
    instruction->size = sizeof(u16) * 2;
    instruction->imm(instruction->address + (this->read<s16>(buffer) * sizeof(u16)));
    instruction->target_op(0);
    return true;
}

bool DalvikAssembler::decode2A(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decode2B(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decode2C(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decode2D(Buffer &buffer, const InstructionPtr &instruction) const { return this->decodeOp3(buffer, instruction, "cmpl-float"); }
bool DalvikAssembler::decode2E(Buffer &buffer, const InstructionPtr &instruction) const { return this->decodeOp3(buffer, instruction, "cmpg-float"); }
bool DalvikAssembler::decode2F(Buffer &buffer, const InstructionPtr &instruction) const { return this->decodeOp3(buffer, instruction, "cmpl-double"); }
bool DalvikAssembler::decode30(Buffer &buffer, const InstructionPtr &instruction) const { return this->decodeOp3(buffer, instruction, "cmpg-double"); }
bool DalvikAssembler::decode31(Buffer &buffer, const InstructionPtr &instruction) const { return this->decodeOp3(buffer, instruction, "cmp-long"); }
bool DalvikAssembler::decode32(Buffer &buffer, const InstructionPtr &instruction) const { return this->decodeIfOp3(buffer, instruction, "eq"); }
bool DalvikAssembler::decode33(Buffer &buffer, const InstructionPtr &instruction) const { return this->decodeIfOp3(buffer, instruction, "ne"); }
bool DalvikAssembler::decode34(Buffer &buffer, const InstructionPtr &instruction) const { return this->decodeIfOp3(buffer, instruction, "lt"); }
bool DalvikAssembler::decode35(Buffer &buffer, const InstructionPtr &instruction) const { return this->decodeIfOp3(buffer, instruction, "ge"); }
bool DalvikAssembler::decode36(Buffer &buffer, const InstructionPtr &instruction) const { return this->decodeIfOp3(buffer, instruction, "gt"); }
bool DalvikAssembler::decode37(Buffer &buffer, const InstructionPtr &instruction) const { return this->decodeIfOp3(buffer, instruction, "le"); }
bool DalvikAssembler::decode38(Buffer &buffer, const InstructionPtr &instruction) const { return this->decodeIfOp3(buffer, instruction, "eqz"); }
bool DalvikAssembler::decode39(Buffer &buffer, const InstructionPtr &instruction) const { return this->decodeIfOp2(buffer, instruction, "nez"); }
bool DalvikAssembler::decode3A(Buffer &buffer, const InstructionPtr &instruction) const { return this->decodeIfOp2(buffer, instruction, "ltz"); }
bool DalvikAssembler::decode3B(Buffer &buffer, const InstructionPtr &instruction) const { return this->decodeIfOp2(buffer, instruction, "gez"); }
bool DalvikAssembler::decode3C(Buffer &buffer, const InstructionPtr &instruction) const { return this->decodeIfOp2(buffer, instruction, "gtz"); }
bool DalvikAssembler::decode3D(Buffer &buffer, const InstructionPtr &instruction) const { return this->decodeIfOp2(buffer, instruction, "lez"); }

bool DalvikAssembler::decode3E(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decode3F(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decode40(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decode41(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decode42(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decode43(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decode44(Buffer &buffer, const InstructionPtr &instruction) const { return this->decodeOp3(buffer, instruction, "aget", InstructionTypes::Load); }
bool DalvikAssembler::decode45(Buffer &buffer, const InstructionPtr &instruction) const { return this->decodeOp3(buffer, instruction, "aget-wide", InstructionTypes::Load); }
bool DalvikAssembler::decode46(Buffer &buffer, const InstructionPtr &instruction) const { return this->decodeOp3(buffer, instruction, "aget-object", InstructionTypes::Load); }
bool DalvikAssembler::decode47(Buffer &buffer, const InstructionPtr &instruction) const { return this->decodeOp3(buffer, instruction, "aget-boolean", InstructionTypes::Load); }
bool DalvikAssembler::decode48(Buffer &buffer, const InstructionPtr &instruction) const { return this->decodeOp3(buffer, instruction, "aget-byte", InstructionTypes::Load); }
bool DalvikAssembler::decode49(Buffer &buffer, const InstructionPtr &instruction) const { return this->decodeOp3(buffer, instruction, "aget-char", InstructionTypes::Load); }
bool DalvikAssembler::decode4A(Buffer &buffer, const InstructionPtr &instruction) const { return this->decodeOp3(buffer, instruction, "aget-short", InstructionTypes::Load); }
bool DalvikAssembler::decode4B(Buffer &buffer, const InstructionPtr &instruction) const { return this->decodeOp3(buffer, instruction, "aput", InstructionTypes::Store); }
bool DalvikAssembler::decode4C(Buffer &buffer, const InstructionPtr &instruction) const { return this->decodeOp3(buffer, instruction, "aput-wide", InstructionTypes::Store); }
bool DalvikAssembler::decode4D(Buffer &buffer, const InstructionPtr &instruction) const { return this->decodeOp3(buffer, instruction, "aput-object", InstructionTypes::Store); }
bool DalvikAssembler::decode4E(Buffer &buffer, const InstructionPtr &instruction) const { return this->decodeOp3(buffer, instruction, "aput-boolean", InstructionTypes::Store); }
bool DalvikAssembler::decode4F(Buffer &buffer, const InstructionPtr &instruction) const { return this->decodeOp3(buffer, instruction, "aput-byte", InstructionTypes::Store); }
bool DalvikAssembler::decode50(Buffer &buffer, const InstructionPtr &instruction) const { return this->decodeOp3(buffer, instruction, "aput-char", InstructionTypes::Store); }
bool DalvikAssembler::decode51(Buffer &buffer, const InstructionPtr &instruction) const { return this->decodeOp3(buffer, instruction, "aput-short", InstructionTypes::Store); }
bool DalvikAssembler::decode52(Buffer &buffer, const InstructionPtr &instruction) const { return this->decodeOp3_f(buffer, instruction, "iget", InstructionTypes::Load); }
bool DalvikAssembler::decode53(Buffer &buffer, const InstructionPtr &instruction) const { return this->decodeOp3_f(buffer, instruction, "iget-wide", InstructionTypes::Load); }
bool DalvikAssembler::decode54(Buffer &buffer, const InstructionPtr &instruction) const { return this->decodeOp3_f(buffer, instruction, "iget-object", InstructionTypes::Load); }
bool DalvikAssembler::decode55(Buffer &buffer, const InstructionPtr &instruction) const { return this->decodeOp3_f(buffer, instruction, "iget-boolean", InstructionTypes::Load); }
bool DalvikAssembler::decode56(Buffer &buffer, const InstructionPtr &instruction) const { return this->decodeOp3_f(buffer, instruction, "iget-byte", InstructionTypes::Load); }
bool DalvikAssembler::decode57(Buffer &buffer, const InstructionPtr &instruction) const { return this->decodeOp3_f(buffer, instruction, "iget-char", InstructionTypes::Load); }
bool DalvikAssembler::decode58(Buffer &buffer, const InstructionPtr &instruction) const { return this->decodeOp3_f(buffer, instruction, "iget-short", InstructionTypes::Load); }
bool DalvikAssembler::decode59(Buffer &buffer, const InstructionPtr &instruction) const { return this->decodeOp3_f(buffer, instruction, "iput", InstructionTypes::Store); }
bool DalvikAssembler::decode5A(Buffer &buffer, const InstructionPtr &instruction) const { return this->decodeOp3_f(buffer, instruction, "iput-wide", InstructionTypes::Store); }
bool DalvikAssembler::decode5B(Buffer &buffer, const InstructionPtr &instruction) const { return this->decodeOp3_f(buffer, instruction, "iput-object", InstructionTypes::Store); }
bool DalvikAssembler::decode5C(Buffer &buffer, const InstructionPtr &instruction) const { return this->decodeOp3_f(buffer, instruction, "iput-boolean", InstructionTypes::Store); }
bool DalvikAssembler::decode5D(Buffer &buffer, const InstructionPtr &instruction) const { return this->decodeOp3_f(buffer, instruction, "iput-byte", InstructionTypes::Store); }
bool DalvikAssembler::decode5E(Buffer &buffer, const InstructionPtr &instruction) const { return this->decodeOp3_f(buffer, instruction, "iput-char", InstructionTypes::Store); }
bool DalvikAssembler::decode5F(Buffer &buffer, const InstructionPtr &instruction) const { return this->decodeOp3_f(buffer, instruction, "iput-short", InstructionTypes::Store); }
bool DalvikAssembler::decode60(Buffer &buffer, const InstructionPtr &instruction) const { return this->decodeOp2_f(buffer, instruction, "sget", InstructionTypes::Load); }
bool DalvikAssembler::decode61(Buffer &buffer, const InstructionPtr &instruction) const { return this->decodeOp2_f(buffer, instruction, "sget-wide", InstructionTypes::Load); }
bool DalvikAssembler::decode62(Buffer &buffer, const InstructionPtr &instruction) const { return this->decodeOp2_f(buffer, instruction, "sget-object", InstructionTypes::Load); }
bool DalvikAssembler::decode63(Buffer &buffer, const InstructionPtr &instruction) const { return this->decodeOp2_f(buffer, instruction, "sget-boolean", InstructionTypes::Load); }
bool DalvikAssembler::decode64(Buffer &buffer, const InstructionPtr &instruction) const { return this->decodeOp2_f(buffer, instruction, "sget-byte", InstructionTypes::Load); }
bool DalvikAssembler::decode65(Buffer &buffer, const InstructionPtr &instruction) const { return this->decodeOp2_f(buffer, instruction, "sget-char", InstructionTypes::Load); }
bool DalvikAssembler::decode66(Buffer &buffer, const InstructionPtr &instruction) const { return this->decodeOp2_f(buffer, instruction, "sget-short", InstructionTypes::Load); }
bool DalvikAssembler::decode67(Buffer &buffer, const InstructionPtr &instruction) const { return this->decodeOp2_f(buffer, instruction, "sput", InstructionTypes::Store); }
bool DalvikAssembler::decode68(Buffer &buffer, const InstructionPtr &instruction) const { return this->decodeOp2_f(buffer, instruction, "sput-wide", InstructionTypes::Store); }
bool DalvikAssembler::decode69(Buffer &buffer, const InstructionPtr &instruction) const { return this->decodeOp2_f(buffer, instruction, "sput-object", InstructionTypes::Store); }
bool DalvikAssembler::decode6A(Buffer &buffer, const InstructionPtr &instruction) const { return this->decodeOp2_f(buffer, instruction, "sput-boolean", InstructionTypes::Store); }
bool DalvikAssembler::decode6B(Buffer &buffer, const InstructionPtr &instruction) const { return this->decodeOp2_f(buffer, instruction, "sput-byte", InstructionTypes::Store); }
bool DalvikAssembler::decode6C(Buffer &buffer, const InstructionPtr &instruction) const { return this->decodeOp2_f(buffer, instruction, "sput-char", InstructionTypes::Store); }
bool DalvikAssembler::decode6D(Buffer &buffer, const InstructionPtr &instruction) const { return this->decodeOp2_f(buffer, instruction, "sput-short", InstructionTypes::Store); }
bool DalvikAssembler::decode6E(Buffer &buffer, const InstructionPtr &instruction) const { return this->decodeInvoke(buffer, instruction, "virtual"); }
bool DalvikAssembler::decode6F(Buffer &buffer, const InstructionPtr &instruction) const { return this->decodeInvoke(buffer, instruction, "super"); }
bool DalvikAssembler::decode70(Buffer &buffer, const InstructionPtr &instruction) const { return this->decodeInvoke(buffer, instruction, "direct"); }
bool DalvikAssembler::decode71(Buffer &buffer, const InstructionPtr &instruction) const { return this->decodeInvoke(buffer, instruction, "static"); }
bool DalvikAssembler::decode72(Buffer &buffer, const InstructionPtr &instruction) const { return this->decodeInvoke(buffer, instruction, "interface"); }

bool DalvikAssembler::decode73(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decode74(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decode75(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decode76(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decode77(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decode78(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decode79(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decode7A(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decode7B(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decode7C(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decode7D(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decode7E(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decode7F(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decode80(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decode81(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decode82(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decode83(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decode84(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decode85(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decode86(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decode87(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decode88(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decode89(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decode8A(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decode8B(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decode8C(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decode8D(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decode8E(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decode8F(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decode90(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decode91(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decode92(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decode93(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decode94(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decode95(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decode96(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decode97(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decode98(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decode99(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decode9A(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decode9B(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decode9C(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decode9D(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decode9E(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decode9F(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decodeA0(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decodeA1(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decodeA2(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decodeA3(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decodeA4(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decodeA5(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decodeA6(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decodeA7(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decodeA8(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decodeA9(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decodeAA(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decodeAB(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decodeAC(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decodeAD(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decodeAE(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decodeAF(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decodeB0(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decodeB1(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decodeB2(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decodeB3(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decodeB4(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decodeB5(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decodeB6(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decodeB7(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decodeB8(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decodeB9(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decodeBA(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decodeBB(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decodeBC(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decodeBD(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decodeBE(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decodeBF(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decodeC0(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decodeC1(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decodeC2(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decodeC3(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decodeC4(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decodeC5(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decodeC6(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decodeC7(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decodeC8(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decodeC9(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decodeCA(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decodeCB(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decodeCC(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decodeCD(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decodeCE(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decodeCF(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decodeD0(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decodeD1(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decodeD2(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decodeD3(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decodeD4(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decodeD5(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decodeD6(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decodeD7(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decodeD8(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decodeD9(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decodeDA(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decodeDB(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decodeDC(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decodeDD(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decodeDE(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decodeDF(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decodeE0(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decodeE1(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decodeE2(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decodeE3(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decodeE4(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decodeE5(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decodeE6(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decodeE7(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decodeE8(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decodeE9(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decodeEA(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decodeEB(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decodeEC(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decodeED(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decodeEE(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decodeEF(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decodeF0(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decodeF1(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decodeF2(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decodeF3(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decodeF4(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decodeF5(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decodeF6(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decodeF7(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decodeF8(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decodeF9(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decodeFA(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decodeFB(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decodeFC(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decodeFD(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decodeFE(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

bool DalvikAssembler::decodeFF(Buffer &buffer, const InstructionPtr &instruction) const
{
    return false;
}

} // namespace REDasm
