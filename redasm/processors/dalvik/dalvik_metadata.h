#ifndef DALVIK_METADATA_H
#define DALVIK_METADATA_H

#include "../../redasm.h"

namespace REDasm {

namespace DalvikOperands {
enum: u32 { Normal = 0, MethodIndex, TypeIndex, StringIndex, FieldIndex,
            ParameterFirst = 0x1000, ParameterLast = 0x2000, ParameterThis = 0x4000 };
}

} // namespace REDasm

#endif // DALVIK_METADATA_H
