#ifndef DEX_UTILS_H
#define DEX_UTILS_H

#include "../../redasm.h"

namespace REDasm {

class DEXUtils
{
    public:
        static s32 getSLeb128(u8 **data);
        static u32 getULeb128(u8 **data);
        static s32 getULeb128p1(u8 **data);
};

} // namespace REDasm

#endif // DEX_UTILS_H
