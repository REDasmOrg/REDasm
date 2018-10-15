#include "metaarm_emulator.h"
#include <capstone.h>

namespace REDasm {

MetaARMEmulator::MetaARMEmulator(DisassemblerAPI *disassembler): Emulator(disassembler)
{
    EMULATE_INSTRUCTION(ARM_INS_LDR, &MetaARMEmulator::emulateLdr);
}

void MetaARMEmulator::emulateLdr(const InstructionPtr &instruction)
{
    u64 memvalue = 0;
    const Operand& op2 = instruction->op(1);

    if(!op2.is(OperandTypes::Memory) || !this->read(op2, &memvalue))
        return;

    this->write(instruction->op(0), memvalue);
}

} // namespace REDasm
