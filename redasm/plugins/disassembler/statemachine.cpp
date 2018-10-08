#include "statemachine.h"
#include <iostream>

namespace REDasm {

StateMachine::StateMachine() { }
bool StateMachine::hasNext() const { return !m_pending.empty(); }

void StateMachine::next()
{
    State pendingstate = m_pending.top();
    m_pending.pop();

    auto it = m_states.find(pendingstate.state);

    if(it == m_states.end())
        std::cout << "Unknown state: " << pendingstate.state << std::endl;
    else
        it->second(&pendingstate);
}

} // namespace REDasm
