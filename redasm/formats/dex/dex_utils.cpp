#include "dex_utils.h"

namespace REDasm {

s32 DEXUtils::getSLeb128(u8 **data)
{
    return static_cast<s32>(DEXUtils::getULeb128(data));
}

u32 DEXUtils::getULeb128(u8 **data)
{
    size_t i = 0;
    u32 value = 0;

    while(**data & 0x80)
    {
        value |= ((**data & 0x7F) << (i * 7));
        (*data)++;
        i++;
    }

    value |= ((**data & 0x7F) << (i * 7));
    (*data)++;
    return value;
}

s32 DEXUtils::getULeb128p1(u8 **data)
{
    return static_cast<s32>(DEXUtils::getULeb128(data)) - 1;
}

} // namespace REDasm
