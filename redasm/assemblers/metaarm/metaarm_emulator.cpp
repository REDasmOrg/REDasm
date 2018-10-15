#include "metaarm_emulator.h"
#include "metaarm.h"
#include <capstone.h>

namespace REDasm {

MetaARMEmulator::MetaARMEmulator(DisassemblerAPI *disassembler): Emulator(disassembler)
{
    EMULATE_INSTRUCTION(ARM_INS_LDR, &MetaARMEmulator::emulateLdr);
}

void MetaARMEmulator::emulate(const InstructionPtr &instruction)
{
    /*
     * https://stackoverflow.com/questions/24091566/why-does-the-arm-pc-register-point-to-the-instruction-after-the-next-one-to-be-e
     *
     * In ARM state:
     *  - The value of the PC is the address of the current instruction plus 8 bytes.
     *
     * In Thumb state:
     *  - For B, BL, CBNZ, and CBZ instructions, the value of the PC is the address
     *    of the current instruction plus 4 bytes.
     *
     *  - For all other instructions that use labels, the value of the PC is the address
     *    of the current instruction plus 4 bytes, with bit[1] of the result cleared
     *    to 0 to make it word-aligned.
     */

    MetaARMAssembler* metaarm = static_cast<MetaARMAssembler*>(m_disassembler->assembler());

    if(metaarm->isTHUMBMode())
    {
        if((instruction->id == ARM_INS_B) || (instruction->id == ARM_INS_BL) || (instruction->id == ARM_INS_CBNZ) || (instruction->id == ARM_INS_CBZ))
            this->regWrite(ARM_REG_PC, instruction->address + 4);
        else
            this->regWrite(ARM_REG_PC, (instruction->address + 4) & 0xFFFFFFFE);
    }
    else
        this->regWrite(ARM_REG_PC, instruction->address + 8);

    Emulator::emulate(instruction);
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
