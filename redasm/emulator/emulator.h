#ifndef EMULATOR_H
#define EMULATOR_H

#include <unordered_map>
#include <stack>
#include "../redasm.h"

namespace REDasm {

class Emulator
{
    private:
        typedef std::unordered_map<register_t, u64> Registers;
        typedef std::stack<u64> Stack;

    public:
        Emulator();
        bool reg(register_t id, u64 *value) const;
        virtual void emulate(const InstructionPtr& instruction) = 0;

    protected:
        Registers m_registers;
        Stack m_stack;
};

} // namespace REDasm

#endif // EMULATOR_H
