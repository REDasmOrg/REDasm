#ifndef ARMTHUMB_H
#define ARMTHUMB_H

#include "../../plugins/plugins.h"

namespace REDasm {

class ARMThumbAssembler : public CapstoneAssemblerPlugin<CS_ARCH_ARM, CS_MODE_THUMB>
{
    public:
        ARMThumbAssembler();
        virtual const char* name() const;
        virtual bool decode(Buffer buffer, const InstructionPtr &instruction);
};

DECLARE_ASSEMBLER_PLUGIN(ARMThumbAssembler, armthumb)

} // namespace REDasm

#endif // ARMTHUMB_H
