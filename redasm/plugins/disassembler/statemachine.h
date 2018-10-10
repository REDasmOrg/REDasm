#ifndef STATEMACHINE_H
#define STATEMACHINE_H

#include <unordered_map>
#include <functional>
#include <stack>
#include "../../redasm.h"

#define REGISTER_STATE(state, cb)                         m_states[state] = std::bind(cb, this, std::placeholders::_1)
#define ENQUEUE_STATE(state, address, index, instruction) m_pending.push({ state, static_cast<address_t>(address), index, instruction })
#define FORWARD_STATE(newstate, state)                    ENQUEUE_STATE(newstate, state->address, state->index, state->instruction)
#define FORWARD_STATE_ADDRESS(newstate, address, state)   ENQUEUE_STATE(newstate, address, state->index, state->instruction)

namespace REDasm {

typedef u32 state_t;

struct State
{
    state_t state;
    address_t address;
    int index;
    InstructionPtr instruction;

    bool isFromOperand() const { return index > -1; }
    const Operand& operand() const { return instruction->op(index); }
};

class StateMachine
{
    protected:
        typedef std::function<void(const State*)> StateCallback;

    public:
        StateMachine();
        bool hasNext() const;
        void next();

    protected:
        std::unordered_map<state_t, StateCallback> m_states;
        std::stack<State> m_pending;
};

} // namespace REDasm

#endif // STATEMACHINE_H
