#include "timer.h"
#include <iostream>

namespace REDasm {

Timer::Timer(): m_running(false) {}

Timer::~Timer()
{
    m_running = false;
    m_mutex.unlock();
}

void Timer::stop() { m_running = false; }

void Timer::tick(TimerCallback cb, std::chrono::milliseconds interval)
{
    if(m_running)
        return;

    m_interval = interval;
    m_running = true;
    m_timercallback = cb;
    m_worker = std::thread(&Timer::work, this);
    m_worker.detach();
}

void Timer::work()
{
    while(m_running)
    {
        timer_lock m_lock(m_mutex);
        m_timercallback();
        m_condition.wait_until(m_lock, clock::now() + m_interval);
    }
}

} // namespace REDasm
