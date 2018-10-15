#ifndef ARM_COMMON_H
#define ARM_COMMON_H

#define ARM_REGISTER(reg) ((reg == ARM_REG_INVALID) ? REGISTER_INVALID : reg)

#include <capstone.h>
#include "../../plugins/assembler/assembler.h"

namespace REDasm {

template<cs_arch arch, size_t mode> class ARMCommonAssembler: public CapstoneAssemblerPlugin<arch, mode>
{
    public:
        ARMCommonAssembler();

    protected:
        virtual void onDecoded(const InstructionPtr& instruction);

    private:
        bool isPC(register_t reg) const { return reg == ARM_REG_PC; };
        void checkB(const InstructionPtr& instruction) const;
        void checkStop(const InstructionPtr& instruction) const;
        void checkLdr(const InstructionPtr& instruction) const;
        void checkJumpT0(const InstructionPtr& instruction) const;
        void checkCallT0(const InstructionPtr& instruction) const;
};

template<cs_arch arch, size_t mode> ARMCommonAssembler<arch, mode>::ARMCommonAssembler(): CapstoneAssemblerPlugin<arch, mode>()
{
    REGISTER_INSTRUCTION(ARM_INS_B, &ARMCommonAssembler::checkB);
    REGISTER_INSTRUCTION(ARM_INS_BL, &ARMCommonAssembler::checkCallT0);
    REGISTER_INSTRUCTION(ARM_INS_BX, &ARMCommonAssembler::checkJumpT0);

    REGISTER_INSTRUCTION(ARM_INS_LDM, &ARMCommonAssembler::checkStop);
    REGISTER_INSTRUCTION(ARM_INS_POP, &ARMCommonAssembler::checkStop);

    REGISTER_INSTRUCTION(ARM_INS_LDR, &ARMCommonAssembler::checkLdr);
}

template<cs_arch arch, size_t mode> void ARMCommonAssembler<arch, mode>::onDecoded(const InstructionPtr &instruction)
{
    CapstoneAssemblerPlugin<arch, mode>::onDecoded(instruction);

    cs_insn* insn = reinterpret_cast<cs_insn*>(instruction->userdata);
    const cs_arm& arm = insn->detail->arm;

    for(size_t i = 0; i < arm.op_count; i++)
    {
        const cs_arm_op& op = arm.operands[i];

        if(op.type == ARM_OP_MEM)
        {
            const arm_op_mem& mem = op.mem;

            if((mem.index == ARM_REG_INVALID) && ARMCommonAssembler::isPC(mem.base)) // [pc]
                instruction->mem(instruction->address + instruction->size + 4 + mem.disp);
            else
                instruction->disp(ARM_REGISTER(mem.base), ARM_REGISTER(mem.index), mem.scale, mem.disp);
        }
        else if(op.type == ARM_OP_REG)
            instruction->reg(op.reg);
        else if(op.type == ARM_OP_IMM)
            instruction->imm(op.imm);
    }
}

template<cs_arch arch, size_t mode> void ARMCommonAssembler<arch, mode>::checkB(const InstructionPtr &instruction) const
{
    const cs_arm& arm = reinterpret_cast<cs_insn*>(instruction->userdata)->detail->arm;

    if(arm.cc != ARM_CC_AL)
        instruction->type |= InstructionTypes::Conditional;

    instruction->targetOp(0);
}

template<cs_arch arch, size_t mode> void ARMCommonAssembler<arch, mode>::checkStop(const InstructionPtr &instruction) const
{
    const cs_arm& arm = reinterpret_cast<cs_insn*>(instruction->userdata)->detail->arm;

    if(arm.cc != ARM_CC_AL)
        return;

    for(const Operand& op : instruction->operands)
    {
        if(!op.is(OperandTypes::Register) || !this->isPC(op.reg.r))
            continue;

        instruction->type = InstructionTypes::Stop;
        break;
    }
}

template<cs_arch arch, size_t mode> void ARMCommonAssembler<arch, mode>::checkLdr(const InstructionPtr &instruction) const
{
    const cs_arm& arm = reinterpret_cast<cs_insn*>(instruction->userdata)->detail->arm;
    instruction->op(1).size = sizeof(u32);

    if((arm.cc == ARM_CC_AL) && this->isPC(instruction->op(0).reg.r))
    {
        instruction->type = InstructionTypes::Stop;
        return;
    }
}

template<cs_arch arch, size_t mode> void ARMCommonAssembler<arch, mode>::checkJumpT0(const InstructionPtr &instruction) const
{
    instruction->type = InstructionTypes::Jump;
    instruction->targetOp(0);
}

template<cs_arch arch, size_t mode> void ARMCommonAssembler<arch, mode>::checkCallT0(const InstructionPtr &instruction) const
{
    instruction->type = InstructionTypes::Call;
    instruction->targetOp(0);
}

} // namespace REDasm

#endif // ARM_COMMON_H
