#include "emulator.h"

namespace REDasm {

Emulator::Emulator() { }

bool Emulator::reg(register_t id, u64* value) const
{
    auto it = m_registers.find(id);

    if(it == m_registers.end())
        return false;

    *value = it->second;
    return true;
}

} // namespace REDasm
