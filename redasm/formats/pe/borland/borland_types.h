#ifndef BORLAND_TYPES_H
#define BORLAND_TYPES_H

#include "../../../redasm.h"

namespace REDasm {

/*
 * Package flags:
 *  bit     meaning
 *  -----------------------------------------------------------------------------------------
 *  0     | 1: never-build                  0: always build
 *  1     | 1: design-time only             0: not design-time only      on => bit 2 = off
 *  2     | 1: run-time only                0: not run-time only         on => bit 1 = off
 *  3     | 1: do not check for dup units   0: perform normal dup unit check
 *  4..25 | reserved
 *  26..27| (producer) 0: pre-V4, 1: undefined, 2: c++, 3: Pascal
 *  28..29| reserved
 *  30..31| 0: EXE, 1: Package DLL, 2: Library DLL, 3: undefined
 */

#define PRODUCER_FLAG(packageinfo) ((packageinfo->flags & 0x0C000000) >> 26)
#define IS_PRE_V4(packageinfo)     (PRODUCER_FLAG(packageinfo) == 0)
#define IS_CPP(packageinfo)        (PRODUCER_FLAG(packageinfo) == 2)
#define IS_PASCAL(packageinfo)     (PRODUCER_FLAG(packageinfo) == 3)

struct PackageInfoHeader
{
    u32 flags, requireCount;
};

} // namespace REDasm

#endif // BORLAND_TYPES_H
