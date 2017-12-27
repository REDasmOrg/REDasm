#ifndef VMIL_INSTRUCTIONS_H
#define VMIL_INSTRUCTIONS_H

#define EMIT_OPCODE_FUNCTION(opcode) inline VMILInstructionPtr emit##opcode(const REDasm::InstructionPtr& instruction, u64 index = 0) { \
                                return emitInstruction(instruction, VMIL::Opcodes::opcode, index); \
                            }

#include "vmil_types.h"

namespace REDasm {
namespace VMIL {

extern VMILInstructionDef instructions[];

VMILInstructionPtr emitInstruction(const REDasm::InstructionPtr& instruction, vmilopcode_t opcode, u64 index = 0);

EMIT_OPCODE_FUNCTION(Add)
EMIT_OPCODE_FUNCTION(Sub)
EMIT_OPCODE_FUNCTION(Mul)
EMIT_OPCODE_FUNCTION(Div)
EMIT_OPCODE_FUNCTION(Mod)
EMIT_OPCODE_FUNCTION(Lsh)
EMIT_OPCODE_FUNCTION(Rsh)
EMIT_OPCODE_FUNCTION(And)
EMIT_OPCODE_FUNCTION(Or)
EMIT_OPCODE_FUNCTION(Xor)
EMIT_OPCODE_FUNCTION(Str)
EMIT_OPCODE_FUNCTION(Ldm)
EMIT_OPCODE_FUNCTION(Stm)
EMIT_OPCODE_FUNCTION(Bisz)
EMIT_OPCODE_FUNCTION(Jcc)
EMIT_OPCODE_FUNCTION(Nop)
EMIT_OPCODE_FUNCTION(Undef)
EMIT_OPCODE_FUNCTION(Unkn)

} // namespace VMIL
} // namespace REDasm

#endif // VMIL_INSTRUCTIONS_H
