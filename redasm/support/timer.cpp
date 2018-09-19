#include "timer.h"
#include <iostream>

namespace REDasm {

Timer::Timer(): m_running(false) { }

Timer::~Timer()
{
    timer_lock m_lock(m_mutex);
    m_running = false;
    m_lock.unlock();
    m_worker.join();
}

bool Timer::running() const { return m_running; }

void Timer::stop()
{
    if(!m_running)
        return;

    m_running = false;
    runningChanged(this);
}

void Timer::tick(TimerCallback cb, std::chrono::milliseconds interval)
{
    if(m_running)
        return;

    if(m_worker.joinable())
        m_worker.join();

    m_interval = interval;
    m_running = true;
    m_timercallback = cb;
    m_worker = std::thread(&Timer::work, this);
    runningChanged(this);
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
