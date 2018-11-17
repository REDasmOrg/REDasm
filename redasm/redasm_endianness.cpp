#include "redasm_endianness.h"

namespace REDasm {
namespace Endianness {

int current()
{
    int i = 1;
    char* p = reinterpret_cast<char*>(&i);

    if (p[0] == 1)
        return Endianness::LittleEndian;

    return Endianness::BigEndian;
}

} // namespace Endianness
} // namespace REDasm
