#ifndef ENDIANNESS_H
#define ENDIANNESS_H

#define RETURN_IF_PLATFORM_IS(endianness) if(Endianness::current() == endianness) return;

#include "../redasm.h"

namespace REDasm {

typedef u32 endianness_t;

namespace Endianness {

enum { LittleEndian = 0, BigEndian = 1, };

int current();

template<typename T> void swap(T& v, int valueendian) {
   RETURN_IF_PLATFORM_IS(valueendian);

   u8* p = reinterpret_cast<u8*>(&v);
   std::reverse(p, p + sizeof(T));
}

template<typename T> void cfbe(T& v) { swap(v, Endianness::BigEndian); }    // Convert FROM BigEndian TO PlatformEndian
template<typename T> void cfle(T& v) { swap(v, Endianness::LittleEndian); } // Convert FROM LittleEndian TO PlatformEndian

} // namespace Endianness
} // namespace REDasm

#endif // ENDIANNESS_H
