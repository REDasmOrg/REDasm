#ifndef STATEMACHINE_H
#define STATEMACHINE_H

#include <unordered_map>
#include <unordered_set>
#include <functional>
#include <stack>
#include "../../../redasm.h"

#define DEFINE_STATES(...)                                      protected: enum: state_t { __VA_ARGS__ };
#define REGISTER_STATE(state, cb)                               m_states[state] = std::bind(cb, this, std::placeholders::_1)
#define ENQUEUE_STATE(state, value, index, instruction)         this->enqueueState(state, static_cast<u64>(value), index, instruction)
#define ENQUEUE_VALUE(state, value)                             ENQUEUE_STATE(state, value, -1, NULL)
#define FORWARD_STATE(newstate, state)                          ENQUEUE_STATE(newstate, state->address, state->index, state->instruction)
#define FORWARD_STATE_VALUE(newstate, value, state)             ENQUEUE_STATE(newstate, value, state->index, state->instruction)

namespace REDasm {

typedef u32 state_t;

struct State
{
    state_t id;

    union {
        u64 u_value;
        s64 s_value;
        address_t address;
    };

    s64 index;
    InstructionPtr instruction;

    bool operator ==(const State& rhs) const { return (id == rhs.id) && (address == rhs.address); }
    bool isFromOperand() const { return index > -1; }
    const Operand& operand() const { return instruction->op(index); }
};

class StateMachine
{
    DEFINE_STATES(UserState = 0x10000000)

    protected:
        typedef std::function<void(State*)> StateCallback;

    public:
        StateMachine();
        bool hasNext() const;
        void next();

    protected:
        void enqueueState(state_t id, u64 value, s64 index, const InstructionPtr& instruction);
        virtual bool validateState(const State& state) const;
        virtual void onNewState(const State& state) const;

    protected:
        std::unordered_map<state_t, StateCallback> m_states;
        std::stack<State> m_pending;
};

} // namespace REDasm

#endif // STATEMACHINE_H
