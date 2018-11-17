#ifndef REDASM_TYPES_H
#define REDASM_TYPES_H

#include <cstdint>
#include <cstddef>

typedef uint8_t  u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef int8_t   s8;
typedef int16_t  s16;
typedef int32_t  s32;
typedef int64_t  s64;

typedef s64 register_t;
typedef u64 address_t;
typedef u64 offset_t;
typedef u64 instruction_id_t;

#endif // REDASM_TYPES_H
