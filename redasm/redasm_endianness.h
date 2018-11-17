#ifndef REDASM_ENDIANNESS_H
#define REDASM_ENDIANNESS_H

#define NEEDS_SWAP(endianness) (Endianness::current() != endianness)

#include <algorithm>
#include "redasm_types.h"

namespace REDasm {

typedef u32 endianness_t;

namespace Endianness {

enum { LittleEndian = 0, BigEndian = 1, };

int current();

template<typename T> T swap(T v, int valueendian) {
   if(!NEEDS_SWAP(valueendian))
       return v;

   u8* p = reinterpret_cast<u8*>(&v);
   std::reverse(p, p + sizeof(T));
   return v;
}

template<typename T> T cfbe(T v) { return swap(v, Endianness::BigEndian); }                // Convert FROM BigEndian TO PlatformEndian
template<typename T> T cfle(T v) { return swap(v, Endianness::LittleEndian); }             // Convert FROM LittleEndian TO PlatformEndian
template<typename T> T cfbe(const T* data) { return cfbe(*data); }
template<typename T> T cfle(const T* data) { return cfle(*data); }

} // namespace Endianness
} // namespace REDasm

#endif // ENDIANNESS_H
