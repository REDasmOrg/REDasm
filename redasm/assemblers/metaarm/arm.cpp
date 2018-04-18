#include "arm.h"
#include "metaarm_emulator.h"

#define ARM_REGISTER(reg) ((reg == ARM_REG_INVALID) ? REGISTER_INVALID : reg)

namespace REDasm {

ARMAssembler::ARMAssembler(): CapstoneAssemblerPlugin<CS_ARCH_ARM, CS_MODE_ARM>()
{

}

const char *ARMAssembler::name() const
{
    return "ARM";
}

u32 ARMAssembler::flags() const
{
    return AssemblerFlags::HasVMIL | AssemblerFlags::EmulateVMIL;
}

bool ARMAssembler::decode(Buffer buffer, const InstructionPtr &instruction)
{
    if(!CapstoneAssemblerPlugin<CS_ARCH_ARM, CS_MODE_ARM>::decode(buffer, instruction))
        return false;

    cs_insn* insn = reinterpret_cast<cs_insn*>(instruction->userdata);
    const cs_arm& arm = insn->detail->arm;

    for(size_t i = 0; i < arm.op_count; i++)
    {
        const cs_arm_op& op = arm.operands[i];

        if(op.type == ARM_OP_MEM)
        {
            const arm_op_mem& mem = op.mem;

            if((mem.index == ARM_REG_INVALID) && this->isPC(mem.base)) // [pc]
                instruction->mem(instruction->address + instruction->size + 4 + mem.disp);
            else
                instruction->disp(ARM_REGISTER(mem.base), ARM_REGISTER(mem.index), mem.scale, mem.disp);
        }
        else if(op.type == ARM_OP_REG)
            instruction->reg(op.reg);
        else if(op.type == ARM_OP_IMM)
            instruction->imm(op.imm);
    }

    this->analyzeInstruction(instruction, insn);
    return true;
}

VMIL::Emulator *ARMAssembler::createEmulator(DisassemblerAPI *disassembler) const
{
    return new MetaARMEmulator(disassembler);
}

Printer *ARMAssembler::createPrinter(DisassemblerAPI *disassembler, SymbolTable *symboltable) const
{
     return new MetaARMPrinter(this->_cshandle, disassembler, symboltable);
}

bool ARMAssembler::isPC(register_t reg) const
{
    return reg == ARM_REG_PC;
}

void ARMAssembler::analyzeInstruction(const InstructionPtr &instruction, cs_insn *insn) const
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
            if((arm.cc == ARM_CC_AL) && this->isPC(instruction->operands[0].reg.r))
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
                if(!it->is(OperandTypes::Register) || !this->isPC(it->reg.r))
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
