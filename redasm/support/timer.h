#ifndef TIMER_H
#define TIMER_H

#define TIMER_INTERVAL 5

#include <condition_variable>
#include <functional>
#include <thread>
#include <mutex>
#include "event.h"

namespace REDasm {

class Timer
{
    using timer_lock = std::unique_lock<std::mutex>;
    using clock = std::chrono::steady_clock;

    public:
        Event<Timer*> runningChanged;

    private:
        typedef std::function<void()> TimerCallback;

    public:
        Timer();
        ~Timer();
        bool running() const;
        void stop();
        void tick(TimerCallback cb, std::chrono::milliseconds interval = std::chrono::milliseconds(TIMER_INTERVAL));

    private:
        void work();

    private:
        bool m_running;
        TimerCallback m_timercallback;
        std::chrono::milliseconds m_interval;
        std::condition_variable m_condition;
        std::thread m_worker;
        std::mutex m_mutex;
};

} // namespace REDasm

#endif // TIMER_H
