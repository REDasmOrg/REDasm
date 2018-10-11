#include "arm_thumb.h"
#include "arm_common.h"

namespace REDasm {

ARMThumbAssembler::ARMThumbAssembler(): ARMCommonAssembler<CS_ARCH_ARM, CS_MODE_THUMB>() { }
const char *ARMThumbAssembler::name() const { return "ARM Thumb mode"; }

} // namespace REDasm
