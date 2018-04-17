#ifndef ARMTHUMB_ASSEMBLER_H
#define ARMTHUMB_ASSEMBLER_H

#include "../../plugins/plugins.h"

namespace REDasm {

class ARMThumbAssembler : public CapstoneAssemblerPlugin<CS_ARCH_ARM, CS_MODE_THUMB>
{
    public:
        ARMThumbAssembler();
        virtual const char* name() const;
};

DECLARE_ASSEMBLER_PLUGIN(ARMThumbAssembler, armthumb)

} // namespace REDasm

#endif // ARMTHUMB_ASSEMBLER_H
