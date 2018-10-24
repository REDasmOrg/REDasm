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
        bool isPC(const Operand& op) const { return op.is(OperandTypes::Register) && this->isPC(op.reg.r); };
        bool isLR(const Operand& op) const { return op.is(OperandTypes::Register) && this->isLR(op.reg.r); };

    protected:
        virtual void onDecoded(const InstructionPtr& instruction);

    private:
        bool isPC(register_t reg) const { return reg == ARM_REG_PC; };
        bool isLR(register_t reg) const { return reg == ARM_REG_LR; };
        void checkB(const InstructionPtr& instruction) const;
        void checkStop(const InstructionPtr& instruction) const;
        void checkLdr(const InstructionPtr& instruction) const;
        void checkJumpT0(const InstructionPtr& instruction) const;
        void checkCallT0(const InstructionPtr& instruction) const;
};

} // namespace REDasm

#include "arm_common.cpp"

#endif // ARM_COMMON_H
