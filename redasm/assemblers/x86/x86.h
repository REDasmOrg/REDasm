#ifndef X86_H
#define X86_H

#include "../../plugins/plugins.h"
#include "x86_printer.h"

#define X86_REGISTER(reg) ((reg == X86_REG_INVALID) ? REGISTER_INVALID : reg)

namespace REDasm {

template<cs_mode mode> class X86Assembler: public CapstoneAssemblerPlugin<CS_ARCH_X86, mode>
{
    public:
        X86Assembler(): CapstoneAssemblerPlugin<CS_ARCH_X86, mode>(), _stacksize(0) { }
        virtual const char* name() const;
        virtual bool decode(Buffer buffer, const InstructionPtr &instruction);
        virtual Printer* createPrinter(DisassemblerAPI *disassembler, SymbolTable *symboltable) const { return new X86Printer(this->_cshandle, disassembler, symboltable); }

    private:
        void analyzeInstruction(const InstructionPtr& instruction);
        s32 localIndex(s64 disp, u32& type) const;
        s32 stackLocalIndex(s64 disp) const;
        bool isSP(register_t reg) const;
        bool isBP(register_t reg) const;
        bool isIP(register_t reg) const;

    private:
        s64 _stacksize;
};

template<cs_mode mode> const char *X86Assembler<mode>::name() const
{
    if(mode == CS_MODE_32)
        return "x86";

    if(mode == CS_MODE_64)
        return "x86_64";

    return "Unknown x86";
}

template<cs_mode mode> bool X86Assembler<mode>::decode(Buffer buffer, const InstructionPtr &instruction)
{
    if(!CapstoneAssemblerPlugin<CS_ARCH_X86, mode>::decode(buffer, instruction))
        return false;

    cs_insn* insn = reinterpret_cast<cs_insn*>(instruction->userdata);
    const cs_x86& x86 = insn->detail->x86;

    for(size_t i = 0; i < x86.op_count; i++)
    {
        const cs_x86_op& op = x86.operands[i];

        if(op.type == X86_OP_MEM) {
            const x86_op_mem& mem = op.mem;
            s32 locindex = -1;

            if((mem.index == X86_REG_INVALID) && mem.disp && this->isBP(mem.base)) // Check locals/arguments
            {
                u32 type = 0;
                locindex = this->localIndex(mem.disp, type);
                instruction->local(locindex, mem.base, mem.disp, type);
            }
            else if(this->_stacksize && this->isSP(mem.base)) // Check locals
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

    this->analyzeInstruction(instruction);
    return true;
}

template<cs_mode mode> s32 X86Assembler<mode>::localIndex(s64 disp, u32& type) const
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

    s32 index = (disp / size);

    if(disp > 0)
        index--; // disp == size -> return_address

    if(index < 0)
        index *= -1;

    return index;
}

template<cs_mode mode> s32 X86Assembler<mode>::stackLocalIndex(s64 disp) const
{
    s32 size = 0;

    if(mode == CS_MODE_16)
        size = 2;
    else if(mode == CS_MODE_32)
        size = 4;
    else if(mode == CS_MODE_64)
        size = 8;

    if(disp > this->_stacksize)
        return -1;

    return (this->_stacksize / size) - (disp / size);
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

template<cs_mode mode> void X86Assembler<mode>::analyzeInstruction(const InstructionPtr &instruction)
{
    switch(instruction->id)
    {
        case X86_INS_JA:
        case X86_INS_JAE:
        case X86_INS_JB:
        case X86_INS_JBE:
        case X86_INS_JCXZ:
        case X86_INS_JECXZ:
        case X86_INS_JE:
        case X86_INS_JG:
        case X86_INS_JGE:
        case X86_INS_JL:
        case X86_INS_JLE:
        case X86_INS_JNE:
        case X86_INS_JNO:
        case X86_INS_JNP:
        case X86_INS_JNS:
        case X86_INS_JO:
        case X86_INS_JP:
        case X86_INS_JS:
        case X86_INS_LOOP:
        case X86_INS_LOOPE:
        case X86_INS_LOOPNE:
        {
            instruction->type |= InstructionTypes::Conditional;

            const Operand& op = instruction->operands[0];

            if(op.is((OperandTypes::Register)))
                break;

            instruction->target_idx = 0;

            if(op.is(OperandTypes::Displacement))
                instruction->target(op.mem.displacement);
            else //if(op.is(OperandTypes::Immediate) || op.is(OperandTypes::Memory))
                instruction->target(op.u_value);

            break;
        }

        case X86_INS_JMP:
        case X86_INS_CALL:
        {
            const Operand& op = instruction->operands[0];

            if(op.is((OperandTypes::Register)))
                break;

            if(op.is(OperandTypes::Displacement) && op.mem.displacementOnly())
                instruction->target(op.mem.displacement);
            else if(op.is(OperandTypes::Immediate) || op.is(OperandTypes::Memory))
                instruction->target(op.u_value);
            else
                break;

            instruction->target_idx = 0;
            break;
        }

        case X86_INS_RET:
        case X86_INS_HLT:
            instruction->type |= InstructionTypes::Stop;
            this->_stacksize = 0;
            break;

        case X86_INS_NOP:
            instruction->type |= InstructionTypes::Nop;
            break;

        case X86_INS_PUSH:
        case X86_INS_PUSHAL:
        case X86_INS_PUSHAW:
        case X86_INS_PUSHF:
        case X86_INS_PUSHFD:
        case X86_INS_PUSHFQ:
            instruction->type |= InstructionTypes::Push;
            break;

        case X86_INS_POP:
        case X86_INS_POPAL:
        case X86_INS_POPAW:
        case X86_INS_POPF:
        case X86_INS_POPFD:
        case X86_INS_POPFQ:
            instruction->type |= InstructionTypes::Pop;
            break;

        case X86_INS_SUB:
        {
            if(!this->_stacksize && this->isSP(instruction->operands[0].reg.r))
                this->_stacksize = instruction->operands[1].u_value;

            break;
        }

        default:
            return;
    }
}

typedef X86Assembler<CS_MODE_16> X86_16Assembler;
typedef X86Assembler<CS_MODE_32> X86_32Assembler;
typedef X86Assembler<CS_MODE_64> X86_64Assembler;

DECLARE_ASSEMBLER_PLUGIN(X86_16Assembler, x86_16)
DECLARE_ASSEMBLER_PLUGIN(X86_32Assembler, x86_32)
DECLARE_ASSEMBLER_PLUGIN(X86_64Assembler, x86_64)

}

#endif // X86_H
