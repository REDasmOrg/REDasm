#ifndef DEX_CONSTANTS_H
#define DEX_CONSTANTS_H

#include "../../redasm.h"

#define DEX_FILE_MAGIC              "dex"
#define DEX_ENDIAN_CONSTANT         0x12345678
#define DEX_REVERSE_ENDIAN_CONSTANT 0x78563412
#define DEX_NO_INDEX                static_cast<s32>(-1)
#define DEX_NO_INDEX_U              static_cast<u32>(DEX_NO_INDEX)

namespace REDasm {

namespace DexAccessFlags {

enum { Public               = 0x1,    Private = 0x2,    Protected    = 0x4,
       Static               = 0x8,    Final   = 0x10,   Synchronized = 0x20,
       Volatile             = 0x40,   Bridge  = 0x40,   Transient    = 0x80,
       VarArgs              = 0x80,   Native  = 0x100,  Interface    = 0x200,
       Abstract             = 0x400,  Strict  = 0x800,  Synthetic    = 0x1000,
       Annotation           = 0x2000, Enum    = 0x8000, Constructor  = 0x10000,
       DeclaredSynchronized = 0x20000 };

}

namespace DexValueFormats {

enum { Byte   = 0x00, Short      = 0x02, Char       = 0x03, Int          = 0x04, Long = 0x06,
       Float  = 0x10, Double     = 0x11, MethodType = 0x15, MethodHandle = 0x16,
       String = 0x17, Type       = 0x18, Field      = 0x19, Method       = 0x1a, Enum = 0x1b,
       Array  = 0x1c, Annotation = 0x1d, Null       = 0x1e, Boolean      = 0x1f };

}

namespace DexTypeCodes {

enum { Header       = 0x0000, StringId             = 0x0001, TypeId               = 0x0002, ProtoId       = 0x0003, FieldId    = 0x0004,
       MethodId     = 0x0005, ClassDef             = 0x0006, CallSiteId           = 0x0007, MethodHandle  = 0x0008,
       MapList      = 0x1000, TypeList             = 0x1001, AnnotationSetRefList = 0x1002, AnnotationSet = 0x1003,
       ClassData    = 0x2000, Code                 = 0x2001, StringData           = 0x2002, DebugInfo     = 0x2003, Annotation = 0x2004,
       EncodedArray = 0x2005, AnnotationsDirectory = 0x2006 };

}

} // namespace REDasm

#endif // DEX_CONSTANTS_H
