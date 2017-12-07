#include "hash.h"

#define POLY 0x8408

namespace REDasm {
namespace Hash {

u16 crc16(const u8 *bytes, u32 length)
{
    u8 i;
    u16 data, crc = 0xFFFF;

    if(length == 0)
        return (~crc);

    do
    {
        for (i = 0, data = static_cast<unsigned int>(0xFF) & *bytes++; i < 8; i++, data >>= 1)
        {
            if((crc & 0x0001) ^ (data & 0x0001))
                crc = (crc >> 1) ^ POLY;
            else
                crc >>= 1;
        }
    }
    while(--length);

    crc = ~crc;
    data = crc;
    crc = (crc << 8) | (data >> 8 & 0xFF);

    return (crc);
}

u16 crc16(const std::vector<u8> &bytes)
{
    return crc16(bytes.data(), bytes.size());
}

} // namespace Hash
} // namespace REDasm
