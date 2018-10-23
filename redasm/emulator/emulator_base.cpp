#include "emulator_base.h"

namespace REDasm {

template<typename T> EmulatorBase<T>::EmulatorBase(DisassemblerAPI* disassembler): Emulator(disassembler) { }

template<typename T> void EmulatorBase<T>::emulate(const InstructionPtr& instruction)
{
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

template<typename T> void EmulatorBase<T>::writeMem(T address, T value) { m_memory[address] = value; }

template<typename T> bool EmulatorBase<T>::readMem(T address, T* value, T size) const
{
    auto it = m_memory.find(address);

    if(it == m_memory.end())
    {
        u64 avalue = 0;

        if(!m_disassembler->readAddress(static_cast<address_t>(address), static_cast<size_t>(size), &avalue))
            return false;

        *value = static_cast<T>(avalue);
    }
    else
        *value = it->second;

    return true;
}

template<typename T> bool EmulatorBase<T>::hasError() const { return flag(ErrorFlag); }

template<typename T> void EmulatorBase<T>::reset(bool resetmemory)
{
    while(!m_stack.empty())
        m_stack.pop();

    if(resetmemory)
        m_memory.clear();

    m_registers.clear();
    m_flags.clear();
}

template<typename T> void EmulatorBase<T>::unhandled(const InstructionPtr &instruction) const
{
    REDasm::log("Unhandled instruction '" + instruction->mnemonic + "' @ " + REDasm::hex(instruction->address, 0, false));
}

template<typename T> void EmulatorBase<T>::fail()
{
    this->flag(ErrorFlag);

    if(m_currentinstruction)
    {
        REDasm::log("WARNING: Emulator in FAIL state, last instruction '" + m_currentinstruction->mnemonic +
                    "' @ " + REDasm::hex(m_currentinstruction->address, 0, false));
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
