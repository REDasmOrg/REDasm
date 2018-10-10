#include "emulatorbase.h"
#include "../plugins/format.h"

namespace REDasm {

EmulatorBase::EmulatorBase(DisassemblerAPI *disassembler): m_disassembler(disassembler), m_state(EmulatorBase::StateOk) { m_document = disassembler->document(); }

bool EmulatorBase::emulate(const InstructionPtr &instruction)
{
    if(m_state == EmulatorBase::StateError)
        return false;

    auto it = m_dispatcher.find(instruction->id);

    if(it != m_dispatcher.end())
    {
        it->second(instruction);
        return true;
    }

    return false;
}

bool EmulatorBase::reg(register_t id, u64* value) const
{
    auto it = m_registers.find(id);

    if(it == m_registers.end())
        return false;

    *value = it->second;
    return true;
}

void EmulatorBase::reset(bool resetmemory)
{
    while(!m_stack.empty())
        m_stack.pop();

    m_registers.clear();

    if(resetmemory)
        m_memory.clear();

    m_state = EmulatorBase::StateOk;
}

void EmulatorBase::fail()
{
    REDasm::log("WARNING: Emulator in FAIL state");
    m_state = EmulatorBase::StateError;
}

void EmulatorBase::unhandled(const InstructionPtr &instruction) const
{
    REDasm::log("Unhandled instruction '" + instruction->mnemonic +
                "' @ " + REDasm::hex(instruction->address, m_disassembler->format()->bits(), false));
}

bool EmulatorBase::computeDisplacement(const DisplacementOperand &dispop, u64 *value)
{
    u64 address = 0;

    if(dispop.base.isValid() && !this->reg(dispop.base.r, &address))
    {
        this->fail();
        return false;
    }

    u64 index = 0;
    address = static_cast<u64>(static_cast<s64>(address) + dispop.displacement);

    if(dispop.index.isValid() && !this->reg(dispop.index.r, &index))
    {
        this->fail();
        return false;
    }

    *value = address + (index * dispop.scale);
    return true;
}

bool EmulatorBase::readMemory(address_t address, size_t size, u64* value)
{
    auto it = m_memory.find(address);

    if(it == m_memory.end())
        return m_disassembler->readAddress(address, size, value);

    *value = it->second;
    return true;
}

void EmulatorBase::writeMemory(address_t address, u64 value) { m_memory[address] = value; }

void EmulatorBase::regCreate(register_t id)
{
    auto it = m_registers.find(id);

    if(it == m_registers.end())
        m_registers[id] = 0;
}

void EmulatorBase::regWrite(register_t id, u64 value) { m_registers[id] = value; }

} // namespace REDasm
