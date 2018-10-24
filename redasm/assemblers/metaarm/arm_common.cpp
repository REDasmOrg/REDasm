#include "arm_common.h"

namespace REDasm {

template<cs_arch arch, size_t mode> ARMCommonAssembler<arch, mode>::ARMCommonAssembler(): CapstoneAssemblerPlugin<arch, mode>()
{
    SET_INSTRUCTION_TYPE(ARM_INS_ADD, InstructionTypes::Add);
    SET_INSTRUCTION_TYPE(ARM_INS_ADC, InstructionTypes::Add);
    SET_INSTRUCTION_TYPE(ARM_INS_SUB, InstructionTypes::Sub);
    SET_INSTRUCTION_TYPE(ARM_INS_SBC, InstructionTypes::Sub);
    SET_INSTRUCTION_TYPE(ARM_INS_RSB, InstructionTypes::Sub);
    SET_INSTRUCTION_TYPE(ARM_INS_RSC, InstructionTypes::Sub);
    SET_INSTRUCTION_TYPE(ARM_INS_LSL, InstructionTypes::Lsh);
    SET_INSTRUCTION_TYPE(ARM_INS_LSR, InstructionTypes::Rsh);
    SET_INSTRUCTION_TYPE(ARM_INS_ASR, InstructionTypes::Rsh);

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

    if((arm.cc == ARM_CC_AL) && this->isPC(instruction->op(0)))
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
