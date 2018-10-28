#include "timer.h"

namespace REDasm {

Timer::Timer(): m_state(Timer::InactiveState) { }
Timer::~Timer() { m_state = Timer::InactiveState; }

size_t Timer::state() const { return m_state; }
bool Timer::active() const { return m_state == Timer::ActiveState; }
bool Timer::paused() const { return m_state == Timer::PausedState; }

void Timer::stop()
{
    if(m_state == Timer::InactiveState)
        return;

    m_state = Timer::InactiveState;
    stateChanged(this);
}

void Timer::pause()
{
    if(m_state != Timer::ActiveState)
        return;

    m_state = Timer::PausedState;
    stateChanged(this);
}

void Timer::resume()
{
    if(m_state != Timer::PausedState)
        return;

    m_state = Timer::ActiveState;
    stateChanged(this);
}

void Timer::tick(TimerCallback cb, std::chrono::milliseconds interval)
{
    if(m_state != Timer::InactiveState)
        return;

    m_interval = interval;
    m_state = Timer::ActiveState;
    m_timercallback = cb;
    stateChanged(this);

    if(getenv("SYNC_MODE"))
    {
        this->workSync();
        return;
    }

    m_future = std::async(&Timer::work, this);
}

void Timer::work()
{
    while(m_state != Timer::InactiveState)
    {
        if(m_state == Timer::ActiveState)
            m_timercallback();

        std::this_thread::sleep_for(m_interval);
    }
}

void Timer::workSync()
{
    while(m_state != Timer::InactiveState)
    {
        if(m_state == Timer::ActiveState)
            m_timercallback();
    }
}

} // namespace REDasm
