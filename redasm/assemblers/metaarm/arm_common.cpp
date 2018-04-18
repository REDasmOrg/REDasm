#include "arm_common.h"

#define ARM_REGISTER(reg) ((reg == ARM_REG_INVALID) ? REGISTER_INVALID : reg)

namespace REDasm {

bool ARMCommon::decode(const InstructionPtr &instruction)
{
    cs_insn* insn = reinterpret_cast<cs_insn*>(instruction->userdata);
    const cs_arm& arm = insn->detail->arm;

    for(size_t i = 0; i < arm.op_count; i++)
    {
        const cs_arm_op& op = arm.operands[i];

        if(op.type == ARM_OP_MEM)
        {
            const arm_op_mem& mem = op.mem;

            if((mem.index == ARM_REG_INVALID) && ARMCommon::isPC(mem.base)) // [pc]
                instruction->mem(instruction->address + instruction->size + 4 + mem.disp);
            else
                instruction->disp(ARM_REGISTER(mem.base), ARM_REGISTER(mem.index), mem.scale, mem.disp);
        }
        else if(op.type == ARM_OP_REG)
            instruction->reg(op.reg);
        else if(op.type == ARM_OP_IMM)
            instruction->imm(op.imm);
    }

    ARMCommon::analyzeInstruction(instruction, insn);
    return true;
}

bool ARMCommon::isPC(register_t reg) { return reg == ARM_REG_PC; }

void ARMCommon::analyzeInstruction(const InstructionPtr &instruction, cs_insn* insn)
{
    const cs_arm& arm = insn->detail->arm;

    switch(insn->id)
    {
        case ARM_INS_B:
        {
            if(arm.cc != ARM_CC_AL)
                instruction->type |= InstructionTypes::Conditional;

            instruction->target_op(0);
            break;
        }

        case ARM_INS_BL:
        case ARM_INS_BX:
        {
            instruction->type = InstructionTypes::Call;
            instruction->target_op(0);
            break;
        }

        case ARM_INS_LDR:
        {
            if((arm.cc == ARM_CC_AL) && ARMCommon::isPC(instruction->operands[0].reg.r))
            {
                instruction->type = InstructionTypes::Stop;
                return;
            }

            Operand& op = instruction->operands[1];

            if(op.is(OperandTypes::Memory))
                op.r();

            break;
        }

        case ARM_INS_LDM:
        case ARM_INS_POP:
        {
            if(arm.cc != ARM_CC_AL)
                return;

            for(auto it = instruction->operands.begin(); it != instruction->operands.end(); it++)
            {
                if(!it->is(OperandTypes::Register) || !ARMCommon::isPC(it->reg.r))
                    continue;

                instruction->type = InstructionTypes::Stop;
                break;
            }

            break;
        }

        default:
            break;
    }
}

} // namespace REDasm
