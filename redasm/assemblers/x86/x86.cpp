#include "x86.h"

namespace REDasm {

template<cs_mode mode> X86Assembler<mode>::X86Assembler(): CapstoneAssemblerPlugin<CS_ARCH_X86, mode>(), m_stacksize(0)
{
    SET_INSTRUCTION_TYPE(X86_INS_JA, InstructionTypes::Conditional);
    SET_INSTRUCTION_TYPE(X86_INS_JAE, InstructionTypes::Conditional);
    SET_INSTRUCTION_TYPE(X86_INS_JB, InstructionTypes::Conditional);
    SET_INSTRUCTION_TYPE(X86_INS_JBE, InstructionTypes::Conditional);
    SET_INSTRUCTION_TYPE(X86_INS_JCXZ, InstructionTypes::Conditional);
    SET_INSTRUCTION_TYPE(X86_INS_JECXZ, InstructionTypes::Conditional);
    SET_INSTRUCTION_TYPE(X86_INS_JE, InstructionTypes::Conditional);
    SET_INSTRUCTION_TYPE(X86_INS_JG, InstructionTypes::Conditional);
    SET_INSTRUCTION_TYPE(X86_INS_JGE, InstructionTypes::Conditional);
    SET_INSTRUCTION_TYPE(X86_INS_JL, InstructionTypes::Conditional);
    SET_INSTRUCTION_TYPE(X86_INS_JLE, InstructionTypes::Conditional);
    SET_INSTRUCTION_TYPE(X86_INS_JNE, InstructionTypes::Conditional);
    SET_INSTRUCTION_TYPE(X86_INS_JNO, InstructionTypes::Conditional);
    SET_INSTRUCTION_TYPE(X86_INS_JNP, InstructionTypes::Conditional);
    SET_INSTRUCTION_TYPE(X86_INS_JNS, InstructionTypes::Conditional);
    SET_INSTRUCTION_TYPE(X86_INS_JO, InstructionTypes::Conditional);
    SET_INSTRUCTION_TYPE(X86_INS_JP, InstructionTypes::Conditional);
    SET_INSTRUCTION_TYPE(X86_INS_JS, InstructionTypes::Conditional);
    SET_INSTRUCTION_TYPE(X86_INS_LOOP, InstructionTypes::Conditional);
    SET_INSTRUCTION_TYPE(X86_INS_LOOPE, InstructionTypes::Conditional);
    SET_INSTRUCTION_TYPE(X86_INS_LOOPNE, InstructionTypes::Conditional);
    SET_INSTRUCTION_TYPE(X86_INS_PUSH, InstructionTypes::Push);
    SET_INSTRUCTION_TYPE(X86_INS_PUSHAL, InstructionTypes::Push);
    SET_INSTRUCTION_TYPE(X86_INS_PUSHAW, InstructionTypes::Push);
    SET_INSTRUCTION_TYPE(X86_INS_PUSHF, InstructionTypes::Push);
    SET_INSTRUCTION_TYPE(X86_INS_PUSHFD, InstructionTypes::Push);
    SET_INSTRUCTION_TYPE(X86_INS_PUSHFQ, InstructionTypes::Push);
    SET_INSTRUCTION_TYPE(X86_INS_POP, InstructionTypes::Pop);
    SET_INSTRUCTION_TYPE(X86_INS_POPAL, InstructionTypes::Pop);
    SET_INSTRUCTION_TYPE(X86_INS_POPAW, InstructionTypes::Pop);
    SET_INSTRUCTION_TYPE(X86_INS_POPF, InstructionTypes::Pop);
    SET_INSTRUCTION_TYPE(X86_INS_POPFD, InstructionTypes::Pop);
    SET_INSTRUCTION_TYPE(X86_INS_POPFQ, InstructionTypes::Pop);
    SET_INSTRUCTION_TYPE(X86_INS_HLT, InstructionTypes::Stop);
    SET_INSTRUCTION_TYPE(X86_INS_RET, InstructionTypes::Stop);
    SET_INSTRUCTION_TYPE(X86_INS_NOP, InstructionTypes::Nop);

    REGISTER_INSTRUCTION(X86_INS_JA, &X86Assembler::setBranchTarget);
    REGISTER_INSTRUCTION(X86_INS_JAE, &X86Assembler::setBranchTarget);
    REGISTER_INSTRUCTION(X86_INS_JB, &X86Assembler::setBranchTarget);
    REGISTER_INSTRUCTION(X86_INS_JBE, &X86Assembler::setBranchTarget);
    REGISTER_INSTRUCTION(X86_INS_JCXZ, &X86Assembler::setBranchTarget);
    REGISTER_INSTRUCTION(X86_INS_JECXZ, &X86Assembler::setBranchTarget);
    REGISTER_INSTRUCTION(X86_INS_JE, &X86Assembler::setBranchTarget);
    REGISTER_INSTRUCTION(X86_INS_JG, &X86Assembler::setBranchTarget);
    REGISTER_INSTRUCTION(X86_INS_JGE, &X86Assembler::setBranchTarget);
    REGISTER_INSTRUCTION(X86_INS_JL, &X86Assembler::setBranchTarget);
    REGISTER_INSTRUCTION(X86_INS_JLE, &X86Assembler::setBranchTarget);
    REGISTER_INSTRUCTION(X86_INS_JNE, &X86Assembler::setBranchTarget);
    REGISTER_INSTRUCTION(X86_INS_JNO, &X86Assembler::setBranchTarget);
    REGISTER_INSTRUCTION(X86_INS_JNP, &X86Assembler::setBranchTarget);
    REGISTER_INSTRUCTION(X86_INS_JNS, &X86Assembler::setBranchTarget);
    REGISTER_INSTRUCTION(X86_INS_JO, &X86Assembler::setBranchTarget);
    REGISTER_INSTRUCTION(X86_INS_JP, &X86Assembler::setBranchTarget);
    REGISTER_INSTRUCTION(X86_INS_JS, &X86Assembler::setBranchTarget);
    REGISTER_INSTRUCTION(X86_INS_JMP, &X86Assembler::setBranchTarget);
    REGISTER_INSTRUCTION(X86_INS_CALL, &X86Assembler::setBranchTarget);
    REGISTER_INSTRUCTION(X86_INS_HLT, &X86Assembler::resetStackSize);
    REGISTER_INSTRUCTION(X86_INS_RET, &X86Assembler::resetStackSize);
    REGISTER_INSTRUCTION(X86_INS_SUB, &X86Assembler::initStackSize);
    REGISTER_INSTRUCTION(X86_INS_LEA, &X86Assembler::checkLea);
}

template<cs_mode mode> const char *X86Assembler<mode>::name() const
{
    if(mode == CS_MODE_32)
        return "x86";

    if(mode == CS_MODE_64)
        return "x86_64";

    return "Unknown x86";
}

template<cs_mode mode> void X86Assembler<mode>::onDecoded(const InstructionPtr &instruction)
{
    CapstoneAssemblerPlugin<CS_ARCH_X86, mode>::onDecoded(instruction);

    cs_insn* insn = reinterpret_cast<cs_insn*>(instruction->userdata);
    const cs_x86& x86 = insn->detail->x86;

    for(size_t i = 0; i < x86.op_count; i++)
    {
        const cs_x86_op& op = x86.operands[i];

        if(op.type == X86_OP_MEM) {
            const x86_op_mem& mem = op.mem;
            s64 locindex = -1;

            if((mem.index == X86_REG_INVALID) && mem.disp && this->isBP(mem.base)) // Check locals/arguments
            {
                u32 type = 0;
                locindex = this->localIndex(mem.disp, type);
                instruction->local(locindex, mem.base, mem.disp, type);
            }
            else if(m_stacksize && this->isSP(mem.base)) // Check locals
            {
                locindex = this->stackLocalIndex(mem.disp);

                if(locindex != -1)
                    instruction->local(locindex, mem.base, mem.disp);
                else // It's not a local...
                    instruction->disp(X86_REGISTER(mem.base), X86_REGISTER(mem.index), mem.scale, mem.disp);
            }
            else if((mem.index == X86_REG_INVALID) && this->isIP(mem.base)) // Handle case [xip + disp]
                instruction->mem(instruction->address + instruction->size + mem.disp);
            else if((mem.index == X86_REG_INVALID) && (mem.base == X86_REG_INVALID)) // Handle case [disp]
                instruction->mem(mem.disp);
            else
                instruction->disp(X86_REGISTER(mem.base), X86_REGISTER(mem.index), mem.scale, mem.disp);
        }
        else if(op.type == X86_OP_IMM)
            instruction->imm(op.imm);
        else if(op.type == X86_OP_REG)
            instruction->reg(op.reg);
    }
}

template<cs_mode mode> s64 X86Assembler<mode>::localIndex(s64 disp, u32& type) const
{
    if(disp > 0)
        type = OperandTypes::Argument;
    else if(disp < 0)
        type = OperandTypes::Local;

    s32 size = 0;

    if(mode == CS_MODE_16)
        size = 2;
    else if(mode == CS_MODE_32)
        size = 4;
    else if(mode == CS_MODE_64)
        size = 8;

    s64 index = (disp / size);

    if(disp > 0)
        index--; // disp == size -> return_address

    if(index < 0)
        index *= -1;

    return index;
}

template<cs_mode mode> s64 X86Assembler<mode>::stackLocalIndex(s64 disp) const
{
    s32 size = 0;

    if(mode == CS_MODE_16)
        size = 2;
    else if(mode == CS_MODE_32)
        size = 4;
    else if(mode == CS_MODE_64)
        size = 8;

    if(disp > this->m_stacksize)
        return -1;

    return (this->m_stacksize / size) - (disp / size);
}

template<cs_mode mode> bool X86Assembler<mode>::isSP(register_t reg) const
{
    if(mode == CS_MODE_16)
        return reg == X86_REG_SP;

    if(mode == CS_MODE_32)
        return reg == X86_REG_ESP;

    if(mode == CS_MODE_64)
        return reg == X86_REG_RSP;

    return false;
}

template<cs_mode mode> bool X86Assembler<mode>::isBP(register_t reg) const
{
    if(mode == CS_MODE_16)
        return reg == X86_REG_BP;

    if(mode == CS_MODE_32)
        return reg == X86_REG_EBP;

    if(mode == CS_MODE_64)
        return reg == X86_REG_RBP;

    return false;
}

template<cs_mode mode> bool X86Assembler<mode>::isIP(register_t reg) const
{
    if(mode == CS_MODE_16)
        return reg == X86_REG_IP;

    if(mode == CS_MODE_32)
        return reg == X86_REG_EIP;

    if(mode == CS_MODE_64)
        return reg == X86_REG_RIP;

    return false;
}

template<cs_mode mode> void X86Assembler<mode>::initStackSize(const InstructionPtr& instruction)
{
    if(!this->m_stacksize && this->isSP(instruction->op(0).reg.r))
        this->m_stacksize = instruction->op(1).u_value;
}

template<cs_mode mode> void X86Assembler<mode>::setBranchTarget(const InstructionPtr& instruction)
{
    Operand& op = instruction->op(0);

    if(!op.isNumeric())
        return;

    instruction->target(op.u_value);
    instruction->target_idx = 0;
}

template<cs_mode mode> void X86Assembler<mode>::checkLea(const InstructionPtr &instruction)
{
    instruction->type = InstructionTypes::Load;

    Operand& op2 = instruction->op(1);

    if(!op2.is(OperandTypes::Memory))
        return;

    op2.type = OperandTypes::Immediate;
}

} // namespace REDasm


