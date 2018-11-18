#include "emulator_base.h"

namespace REDasm {

template<typename T> EmulatorBase<T>::EmulatorBase(DisassemblerAPI* disassembler): Emulator(disassembler), m_sp(0) { }

template<typename T> void EmulatorBase<T>::emulate(const InstructionPtr& instruction)
{
    if(!this->hasError() && m_memory.empty())
        this->fail();

    if(this->hasError())
        return;

    Emulator::emulate(instruction);
}

template<typename T> bool EmulatorBase<T>::readOp(const Operand &op, T* value)
{
    if(op.is(OperandTypes::Displacement))
    {
        if(this->displacementT(op.disp, value))
            return true;

        REDasm::log("Error reading displacement operand " + std::to_string(op.index));
        this->fail();
        return false;
    }

    if(op.is(OperandTypes::Register))
    {
        *value = this->readReg(op.reg.r);
        return true;
    }

    if(op.is(OperandTypes::Memory))
    {
        if(this->readMem(op.u_value, value, op.size))
            return true;

        REDasm::log("Error reading memory operand " + std::to_string(op.index));
        this->fail();
        return false;
    }

    *value = op.u_value;
    return true;
}

template<typename T> void EmulatorBase<T>::writeOp(const Operand &op, T value)
{
    if(op.is(OperandTypes::Displacement))
    {
        if(!this->displacementT(op.disp, &value))
            this->fail();
    }
    else if(op.is(OperandTypes::Memory))
        this->writeMem(op.u_value, value);
    else if(op.is(OperandTypes::Register))
        this->writeReg(op.reg.r, value);
    else
        this->fail();
}

template<typename T> void EmulatorBase<T>::flag(T flag, bool set)
{
    if(set)
        m_flags.insert(flag);
    else
        m_flags.erase(flag);
}

template<typename T> bool EmulatorBase<T>::flag(T flag) const { return m_flags.find(flag) != m_flags.end(); }
template<typename T> void EmulatorBase<T>::writeReg(T r, T value) { m_registers[r] = value; }

template<typename T> T EmulatorBase<T>::readReg(T r) const
{
    auto it = m_registers.find(r);

    if(it != m_registers.end())
        return it->second;

    return 0;
}

template<typename T> void EmulatorBase<T>::changeReg(const Operand &op, ST amount)
{
    if(!op.is(OperandTypes::Register) || !amount)
        return;

    this->writeReg(op.reg.r, this->readReg(op.reg.r) + amount);
}

template<typename T> void EmulatorBase<T>::changeSP(ST amount)
{
    if(!amount)
        return;

    if((amount < 0) && ((m_sp - amount) > STACK_SIZE))
    {
        REDasm::log("Stack Overflow: trying to allocate " + std::to_string(std::abs(amount)) + " bytes");
        this->fail();
        return;
    }

    if((amount > m_sp))
    {
        REDasm::log("Stack Underflow: trying to claim " + std::to_string(amount) + " bytes, SP is " + std::to_string(m_sp));
        this->fail();
        return;
    }

    m_sp -= amount;
}

template<typename T> bool EmulatorBase<T>::writeMem(T address, T value, T size)
{
    BufferRef memory = this->getMemory(address);

    if(memory.eob())
        return false;

    if(size == sizeof(u8))
        memory = static_cast<u8>(value);
    else if(size == sizeof(u16))
        memory = static_cast<u16>(value);
    else if(size == sizeof(u32))
        memory = static_cast<u32>(value);
    else if(size == sizeof(u64))
        memory = static_cast<u64>(value);
    else
    {
        REDasm::log("WriteMemory: Invalid size (" + std::to_string(size) + ")");
        this->fail();
    }

    return true;
}

template<typename T> bool EmulatorBase<T>::readMem(T address, T* value, T size)
{
    BufferRef memory = this->getMemory(address);

    if(memory.eob())
        return false;

    if(size == sizeof(u8))
        *value = static_cast<u8>(memory);
    else if(size == sizeof(u16))
        *value = static_cast<u16>(memory);
    else if(size == sizeof(u32))
        *value = static_cast<u32>(memory);
    else if(size == sizeof(u64))
        *value = static_cast<u64>(memory);
    else
    {
        REDasm::log("ReadMemory: Invalid size (" + std::to_string(size) + ")");
        this->fail();
    }

    return true;
}

template<typename T> bool EmulatorBase<T>::hasError() const { return flag(ErrorFlag); }

template<typename T> void EmulatorBase<T>::reset(bool resetmemory)
{
    if(resetmemory)
        this->remap();

    m_registers.clear();
    m_flags.clear();
}

template<typename T> void EmulatorBase<T>::unhandled(const InstructionPtr &instruction) const
{
    REDasm::log("Unhandled instruction '" + instruction->mnemonic + "' @ " + REDasm::hex(instruction->address));
}

template<typename T> void EmulatorBase<T>::fail()
{
    this->flag(ErrorFlag);

    if(m_currentinstruction)
    {
        REDasm::log("WARNING: Emulator in FAIL state, last instruction '" + m_currentinstruction->mnemonic +
                    "' @ " + REDasm::hex(m_currentinstruction->address));
    }
    else
        REDasm::log("WARNING: Emulator in FAIL state");
}

template<typename T> bool EmulatorBase<T>::displacementT(const DisplacementOperand &dispop, T* value)
{
    T address = 0;

    if(dispop.base.isValid())
        address = this->readReg(dispop.base.r);

    address += static_cast<typename std::make_signed<T>::type>(dispop.displacement);

    T index = 0;

    if(dispop.index.isValid())
        index = this->readReg(dispop.index.r);

    *value = address + (index * dispop.scale);
    return true;
}


} // namespace REDasm
