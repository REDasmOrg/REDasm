#include "emulatorbase.h"
#include "../plugins/format.h"

namespace REDasm {

EmulatorBase::EmulatorBase(DisassemblerAPI *disassembler): m_disassembler(disassembler), m_state(EmulatorBase::StateOk) { m_document = disassembler->document(); }

bool EmulatorBase::emulate(const InstructionPtr &instruction)
{
    if(m_state == EmulatorBase::StateError)
        return false;

    m_currentinstruction = instruction;

    auto it = m_dispatcher.find(instruction->id);

    if(it != m_dispatcher.end())
    {
        it->second(instruction);
        return true;
    }

    return false;
}

bool EmulatorBase::computeDisplacement(const Operand &op, u64 *value)
{
    if(!op.is(OperandTypes::Displacement))
        return false;

    return this->computeDisplacement(op.disp, value);
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

bool EmulatorBase::hasError() const { return m_state == EmulatorBase::StateError; }

void EmulatorBase::fail()
{
    m_state = EmulatorBase::StateError;

    if(m_currentinstruction)
    {
        REDasm::log("WARNING: Emulator in FAIL state, last instruction '" + m_currentinstruction->mnemonic +
                    "' @ " + REDasm::hex(m_currentinstruction->address, m_disassembler->format()->bits(), false));
    }
    else
        REDasm::log("WARNING: Emulator in FAIL state");
}

void EmulatorBase::unhandled(const InstructionPtr &instruction) const
{
    REDasm::log("Unhandled instruction '" + instruction->mnemonic +
                "' @ " + REDasm::hex(instruction->address, m_disassembler->format()->bits(), false));
}

bool EmulatorBase::computeDisplacement(const DisplacementOperand &dispop, u64 *value)
{
    u64 address = 0;

    if(dispop.base.isValid())
        address = this->regRead(dispop.base.r);

    u64 index = 0;
    address = static_cast<u64>(static_cast<s64>(address) + dispop.displacement);

    if(dispop.index.isValid())
        index = this->regRead(dispop.index.r);

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

u64 EmulatorBase::regRead(register_t id) const
{
    auto it = m_registers.find(id);

    if(it == m_registers.end())
        return 0;

    return it->second;
}

void EmulatorBase::regWrite(register_t id, u64 value) { m_registers[id] = value; }

} // namespace REDasm
