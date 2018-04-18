#include "armthumb.h"

namespace REDasm {

ARMThumbAssembler::ARMThumbAssembler(): CapstoneAssemblerPlugin<CS_ARCH_ARM, CS_MODE_THUMB>()
{

}

const char *ARMThumbAssembler::name() const
{
    return "ARM Thumb mode";
}

} // namespace REDasm
