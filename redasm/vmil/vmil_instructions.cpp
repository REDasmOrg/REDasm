#include "vmil_instructions.h"

#define VMIL_INSTRUCTION(ins, type) { VMIL_INS_##ins, VMIL::Opcodes::type, InstructionTypes::type }
#define VMIL_INSTRUCTION_T(ins, t1, t2) { VMIL_INS_##ins, VMIL::Opcodes::t1, InstructionTypes::t2 }
#define VMIL_INSTRUCTION_TB(ins, t1, t2, t3) { VMIL_INS_##ins, VMIL::Opcodes::t1, InstructionTypes::t2 | InstructionTypes::t3 }

namespace REDasm {
namespace VMIL {

VMILInstructionDef instructions[] = { VMIL_INSTRUCTION(ADD, Add),
                                      VMIL_INSTRUCTION(SUB, Sub),
                                      VMIL_INSTRUCTION(MUL, Mul),
                                      VMIL_INSTRUCTION(DIV, Div),
                                      VMIL_INSTRUCTION(MOD, Mod),
                                      VMIL_INSTRUCTION(LSH, Lsh),
                                      VMIL_INSTRUCTION(RSH, Rsh),
                                      VMIL_INSTRUCTION(AND, And),
                                      VMIL_INSTRUCTION(OR, Or),
                                      VMIL_INSTRUCTION(XOR, Xor),
                                      VMIL_INSTRUCTION_T(STR, Str, Store),
                                      VMIL_INSTRUCTION_T(LDM, Ldm, Load),
                                      VMIL_INSTRUCTION_T(STM, Stm, Store),
                                      VMIL_INSTRUCTION_T(BISZ, Bisz, Compare),
                                      VMIL_INSTRUCTION_TB(JCC, Jcc, Jump, Conditional),
                                      VMIL_INSTRUCTION_T(DEF, Def, None),
                                      VMIL_INSTRUCTION_T(UNDEF, Undef, None),
                                      VMIL_INSTRUCTION(NOP, Nop),
                                      VMIL_INSTRUCTION_T(UNKN, Unkn, None) };

VMILInstructionPtr emitInstruction(const REDasm::InstructionPtr& instruction, vmilopcode_t opcode, u64 index) {
    const VMIL::VMILInstructionDef& vmilinstruction = VMIL::instructions[opcode];

    VMILInstructionPtr vminstruction = std::make_shared<VMILInstruction>();
    vminstruction->address = VMIL_INSTRUCTION_ADDRESS_I(instruction, index);
    vminstruction->mnemonic = vmilinstruction.mnemonic;
    vminstruction->id = vmilinstruction.id;
    vminstruction->type = vmilinstruction.type;
    vminstruction->blocktype = instruction->blocktype;

    return vminstruction;
}

} // namespace VMIL
} // namespace REDasm
