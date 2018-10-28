#include "statemachine.h"
#include <iostream>

namespace REDasm {

StateMachine::StateMachine() { }
bool StateMachine::hasNext() const { return !m_pending.empty(); }

void StateMachine::next()
{
    State currentstate = m_pending.top();
    m_pending.pop();

    if(!this->validateState(currentstate))
        return;

    auto it = m_states.find(currentstate.id);

    if(it != m_states.end())
    {
        this->onNewState(currentstate);
        it->second(&currentstate);
        return;
    }

    REDasm::log("Unknown state: " + std::to_string(currentstate.id));
}

void StateMachine::enqueueState(state_t state, u64 value, s64 index, const InstructionPtr &instruction)
{
    m_pending.push({ state, static_cast<u64>(value), index, instruction });
}

bool StateMachine::validateState(const State &state) const
{
    RE_UNUSED(state);
    return true;
}

void StateMachine::onNewState(const State &state) const { RE_UNUSED(state); }

} // namespace REDasm
