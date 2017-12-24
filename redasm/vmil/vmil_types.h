#ifndef VMIL_TYPES_H
#define VMIL_TYPES_H

#include "../redasm.h"

#define VMIL_INS_ADD   "add"
#define VMIL_INS_SUB   "sub"
#define VMIL_INS_MUL   "mul"
#define VMIL_INS_DIV   "div"
#define VMIL_INS_MOD   "mod"
#define VMIL_INS_LSH   "lsh"
#define VMIL_INS_RSH   "rsh"
#define VMIL_INS_AND   "and"
#define VMIL_INS_OR    "or"
#define VMIL_INS_XOR   "xor"
#define VMIL_INS_STR   "str"
#define VMIL_INS_LDM   "ldm"
#define VMIL_INS_STM   "stm"
#define VMIL_INS_BISZ  "bisz"
#define VMIL_INS_JCC   "jcc"
#define VMIL_INS_NOP   "nop"
#define VMIL_INS_UNDEF "undef"
#define VMIL_INS_UNKN  "unkn"

#define VMIL_REG_OPERAND                 1
#define VMIL_TRUE                        1
#define VMIL_FALSE                       0
#define VMIL_ADDRESS_SHIFT               0x100
#define VMIL_ADDRESS(instruction, idx)   ((instruction->address * VMIL_ADDRESS_SHIFT) + idx)

namespace REDasm {
namespace VMIL {

enum Opcodes: u32
{
    Add, Sub, Mul, Div, Mod, Lsh, Rsh, // Math Opcodes
    And, Or, Xor,                      // Bitwise Opcodes
    Str, Ldm, Stm,                     // Data Transfer Opcodes
    Bisz, Jcc,                         // Logical Opcodes
    Nop, Undef, Unkn,                  // Other Opcodes
};

struct VMILInstructionDef { std::string mnemonic; u32 id, type; };

typedef Instruction VMILInstruction;
typedef InstructionPtr VMILInstructionPtr;

} // namespace VMIL
} // namespace REDasm

#endif // VMIL_TYPES_H
