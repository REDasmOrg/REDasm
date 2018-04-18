#include "armthumb.h"
#include "arm_common.h"

namespace REDasm {

ARMThumbAssembler::ARMThumbAssembler(): CapstoneAssemblerPlugin<CS_ARCH_ARM, CS_MODE_THUMB>()
{

}

const char *ARMThumbAssembler::name() const
{
    return "ARM Thumb mode";
}

bool ARMThumbAssembler::decode(Buffer buffer, const InstructionPtr &instruction)
{
    if(!CapstoneAssemblerPlugin<CS_ARCH_ARM, CS_MODE_THUMB>::decode(buffer, instruction))
        return false;

    return ARMCommon::decode(instruction);
}

} // namespace REDasm
