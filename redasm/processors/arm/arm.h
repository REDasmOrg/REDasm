#ifndef ARM_H
#define ARM_H

#include "../../plugins/plugins.h"

namespace REDasm {

class ARMProcessor: public CapstoneProcessorPlugin<CS_ARCH_ARM, CS_MODE_ARM>
{
    public:
        ARMProcessor();
        virtual const char* name() const;
        virtual bool decode(Buffer buffer, const InstructionPtr &instruction);
        virtual bool target(const InstructionPtr& instruction, address_t *target, int* index = NULL) const;

    private:
        bool isPC(register_t reg) const;
        void analyzeInstruction(const InstructionPtr& instruction, cs_insn* insn) const;
};

DECLARE_PROCESSOR_PLUGIN(arm, ARMProcessor)

} // namespace REDasm

#endif // ARM_H
