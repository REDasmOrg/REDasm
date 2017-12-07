#ifndef HASH_H
#define HASH_H

#include "../redasm.h"

namespace REDasm {
namespace Hash {

u16 crc16(const u8* bytes, u32 length);
u16 crc16(const std::vector<u8>& bytes);

} // namespace Hash
} // namespace REDasm

#endif // HASH_H
