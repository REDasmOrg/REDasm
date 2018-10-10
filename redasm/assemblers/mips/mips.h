#ifndef MIPS_H
#define MIPS_H

#include "../../plugins/plugins.h"
#include "mips_printer.h"
#include "mips_emulator.h"
#include "mips_quirks.h"

namespace REDasm {

template<size_t mode> class MIPSAssembler: public CapstoneAssemblerPlugin<CS_ARCH_MIPS, mode>
{
    public:
        MIPSAssembler(): CapstoneAssemblerPlugin<CS_ARCH_MIPS, mode>() { }
        virtual const char* name() const;
        virtual u32 flags() const { return AssemblerFlags::HasEmulator; }
        virtual bool decode(Buffer buffer, const InstructionPtr &instruction);
        virtual Emulator* createEmulator(DisassemblerAPI *disassembler) const { return new MIPSEmulator(disassembler); }
        virtual Printer* createPrinter(DisassemblerAPI* disassembler) const { return new MIPSPrinter(this->m_cshandle, disassembler); }

    private:
        void analyzeInstruction(const InstructionPtr &instruction) const;
};

template<size_t mode> const char *MIPSAssembler<mode>::name() const
{
    if(mode & CS_MODE_32)
        return "MIPS32";

    if(mode & CS_MODE_64)
        return "MIPS64";

    return "Unknown MIPS";
}

template<size_t mode> bool MIPSAssembler<mode>::decode(Buffer buffer, const InstructionPtr& instruction)
{
    if(!CapstoneAssemblerPlugin<CS_ARCH_MIPS, mode>::decode(buffer, instruction))
        return MIPSQuirks::decode(buffer, instruction); // Handle COP2 instructions and more

    cs_insn* insn = reinterpret_cast<cs_insn*>(instruction->userdata);
    const cs_mips& mips = insn->detail->mips;

    for(size_t i = 0; i < mips.op_count; i++)
    {
        const cs_mips_op& op = mips.operands[i];

        if(op.type == MIPS_OP_MEM)
            instruction->disp(op.mem.base, op.mem.disp);
        else if(op.type == MIPS_OP_REG)
            instruction->reg(op.reg);
        else if(op.type == MIPS_OP_IMM)
            instruction->imm(op.imm);
    }

    this->analyzeInstruction(instruction);
    return true;
}

template<size_t mode> void MIPSAssembler<mode>::analyzeInstruction(const InstructionPtr& instruction) const
{
    switch(instruction->id)
    {
        case MIPS_INS_ADD:
        case MIPS_INS_ADDI:
        case MIPS_INS_ADDU:
        case MIPS_INS_ADDIU:
        case MIPS_INS_AND:
        case MIPS_INS_ANDI:
        case MIPS_INS_MUL:
        //case MIPS_INS_NOR:
        case MIPS_INS_OR:
        case MIPS_INS_ORI:
        case MIPS_INS_SUB:
        case MIPS_INS_SUBU:
        case MIPS_INS_XOR:
        case MIPS_INS_XORI:
            instruction->op(0).w();
            break;

        case MIPS_INS_J:
            instruction->type = InstructionTypes::Jump;
            instruction->target_op(0);
            break;

        case MIPS_INS_JR:
        {
            instruction->type = InstructionTypes::Jump;

            if(instruction->op(0).reg.r != MIPS_REG_RA)
                instruction->target_idx = 0;

            break;
        }

        case MIPS_INS_JAL:
        case MIPS_INS_BAL:
            instruction->type |= InstructionTypes::Call;
            instruction->target_op(0);
            break;

        case MIPS_INS_BEQZ:
        case MIPS_INS_BNEZ:
        case MIPS_INS_BNEL:
        case MIPS_INS_BLEZ:
        case MIPS_INS_BLEZC:
        case MIPS_INS_BLEZL:
        case MIPS_INS_BGTZ:
        case MIPS_INS_BGEZ:
        case MIPS_INS_BGEZC:
        case MIPS_INS_BGEZL:
        case MIPS_INS_BGEZAL:
        case MIPS_INS_BGEZALL:
        case MIPS_INS_BLTZ:
            instruction->type |= InstructionTypes::Conditional;
            instruction->target_op(1);
            break;

        case MIPS_INS_BNE:
        case MIPS_INS_BEQ:
            instruction->type |= InstructionTypes::Conditional;
            instruction->target_op(2);
            break;

        case MIPS_INS_BREAK:
            instruction->type |= InstructionTypes::Stop;
            break;

        case MIPS_INS_NOP:
            instruction->type |= InstructionTypes::Nop;
            break;

        default:
            break;
    }
}

typedef MIPSAssembler<CS_MODE_MIPS64> MIPS32Assembler;
typedef MIPSAssembler<CS_MODE_MIPS64> MIPS64Assembler;

DECLARE_ASSEMBLER_PLUGIN(MIPS32Assembler, mips32)
DECLARE_ASSEMBLER_PLUGIN(MIPS64Assembler, mips64)

}

#endif // MIPS_H
