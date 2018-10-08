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
        Event<Timer*> stateChanged;

    public:
        enum : size_t { InactiveState = 0, ActiveState, PausedState };

    private:
        typedef std::function<void()> TimerCallback;

    public:
        Timer();
        ~Timer();
        size_t state() const;
        bool active() const;
        bool paused() const;
        void stop();
        void pause();
        void resume();
        void tick(TimerCallback cb, std::chrono::milliseconds interval = std::chrono::milliseconds(TIMER_INTERVAL));

    private:
        void work();
        void workSync();

    private:
        bool m_running;
        size_t m_state;
        TimerCallback m_timercallback;
        std::chrono::milliseconds m_interval;
        std::condition_variable m_condition;
        std::thread m_worker;
        std::mutex m_mutex;
};

} // namespace REDasm

#endif // TIMER_H
