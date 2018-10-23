#include "emulator_type.h"

namespace REDasm {

template<typename T> EmulatorT<T>::EmulatorT(DisassemblerAPI *disassembler): EmulatorALU<T>(disassembler) { }

template<typename T> bool EmulatorT<T>::read(const Operand &op, u64* value)
{
    T tvalue = 0;

    if(!this->readOp(op, &tvalue))
        return false;

    *value = static_cast<u64>(tvalue);
    return true;
}

template<typename T> void EmulatorT<T>::moveOp(const InstructionPtr &instruction, int opdest, int opsrc)
{
    T value = 0;

    if(!this->readOp(instruction->op(opsrc), &value))
        return;

    this->writeOp(instruction->op(opdest), value);
}

} // namespace REDasm
