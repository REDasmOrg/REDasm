#ifndef MIPS_H
#define MIPS_H

#include "../../plugins/plugins.h"
#include "mipsprinter.h"
#include "mipsquirks.h"

namespace REDasm {

template<size_t mode> class MIPSProcessor: public CapstoneProcessorPlugin<CS_ARCH_MIPS, mode>
{
    public:
        MIPSProcessor(): CapstoneProcessorPlugin<CS_ARCH_MIPS, mode>() { }
        virtual const char* name() const;
        virtual int flags() const { return ProcessorFlags::DelaySlot; }
        virtual bool decode(Buffer buffer, const InstructionPtr &instruction);
        virtual Printer* createPrinter(DisassemblerFunctions* disassembler, SymbolTable *symboltable) const { return new MIPSPrinter(this->_cshandle, disassembler, symboltable); }

    private:
        bool makePseudo(const InstructionPtr &instruction1, const InstructionPtr &instruction2, const InstructionPtr& instructionout);
        bool decodeMips(Buffer &buffer, const InstructionPtr &instruction);
        bool checkDecodePseudo(Buffer buffer, const InstructionPtr &instruction);
        void analyzeInstruction(const InstructionPtr &instruction) const;
};

template<size_t mode> const char *MIPSProcessor<mode>::name() const
{
    if(mode & CS_MODE_32)
        return "MIPS32 Processor";

    if(mode & CS_MODE_64)
        return "MIPS64 Processor";

    return "Unknown MIPS Processor";
}

template<size_t mode> bool MIPSProcessor<mode>::decodeMips(Buffer& buffer, const InstructionPtr& instruction)
{
    if(!CapstoneProcessorPlugin<CS_ARCH_MIPS, mode>::decode(buffer, instruction))
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

template<size_t mode> bool MIPSProcessor<mode>::decode(Buffer buffer, const InstructionPtr& instruction)
{
    if(!this->decodeMips(buffer, instruction))
        return false;

    this->checkDecodePseudo(buffer, instruction);
    return true;
}

template<size_t mode> bool MIPSProcessor<mode>::makePseudo(const InstructionPtr &instruction1, const InstructionPtr& instruction2, const InstructionPtr &instructionout)
{
    const OperandList operands1 = instruction1->operands;
    const OperandList operands2 = instruction2->operands;

    if((operands2.size() == 0) || (operands2.size() > 3))
        return false;

    if((operands2.size() == 3) && (operands1[0].reg.r != operands2[1].reg.r))
        return false;

    if((operands2.size() == 2) && (operands1[0].reg.r != operands2[1].mem.base.r))
        return false;

    const cs_insn* insn1 = reinterpret_cast<cs_insn*>(instruction1->userdata);
    const cs_insn* insn2 = reinterpret_cast<cs_insn*>(instruction2->userdata);

    s64 imm1 = operands1[1].s_value;

    if(insn1->id == MIPS_INS_LUI)
        imm1 <<= 16;

    switch(insn2->id)
    {
        case MIPS_INS_ADDIU:
        {
            instructionout->reset();
            instructionout->mnemonic = "li";
            instructionout->op(operands2[0]).imm(imm1 + operands2[2].s_value);
            break;
        }

        case MIPS_INS_ORI:
        {
            instructionout->reset();
            instructionout->mnemonic = "li";
            instructionout->op(operands1[0]).imm(imm1 | operands2[2].s_value);
            break;
        }

        case MIPS_INS_LW:
        case MIPS_INS_SW:
        case MIPS_INS_LH:
        case MIPS_INS_SH:
        {
            instructionout->reset();
            instructionout->mnemonic = insn2->mnemonic;
            instructionout->op(operands2[0]).mem(imm1 + operands2[1].mem.displacement);
            break;
        }

        case MIPS_INS_LHU:
        {
            instructionout->reset();
            instructionout->mnemonic = "lhu";
            instructionout->op(operands2[0]).mem(imm1 + operands2[1].mem.displacement);
            break;
        }

        default:
            return false;
    }

    instructionout->bytes += instruction2->bytes;
    instructionout->size += instruction2->size;
    return true;
}

template<size_t mode> bool MIPSProcessor<mode>::checkDecodePseudo(Buffer buffer, const InstructionPtr &instruction)
{
    cs_insn* insn1 = reinterpret_cast<cs_insn*>(instruction->userdata);

    if(!insn1)
        return false;

    InstructionPtr nextinstruction = std::make_shared<Instruction>();
    buffer += insn1->size;

    if(!this->decodeMips(buffer, nextinstruction))
        return false;

    cs_insn* insn2 = reinterpret_cast<cs_insn*>(nextinstruction->userdata);

    if(!insn2)
        return false;

    if(insn2->id == MIPS_INS_LUI)
    {
        nextinstruction->address = instruction->address;
        return this->makePseudo(nextinstruction, instruction, instruction);
    }
    else if(insn1->id == MIPS_INS_LUI)
        return this->makePseudo(instruction, nextinstruction, instruction);

    return false;
}

template<size_t mode> void MIPSProcessor<mode>::analyzeInstruction(const InstructionPtr& instruction) const
{
    switch(instruction->id)
    {
        case MIPS_INS_J:
            instruction->target_op(0);
            break;

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

typedef MIPSProcessor<CS_MODE_MIPS64> MIPS32Processor;
typedef MIPSProcessor<CS_MODE_MIPS64 | CS_MODE_MIPSGP64> MIPS64Processor;

DECLARE_PROCESSOR_PLUGIN(mips32, MIPS32Processor)
DECLARE_PROCESSOR_PLUGIN(mips64, MIPS64Processor)

}

#endif // MIPS_H
