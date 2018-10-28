#ifndef TIMER_H
#define TIMER_H

#define TIMER_INTERVAL 1 // 1ms

#include <condition_variable>
#include <functional>
#include <future>
#include "event.h"

namespace REDasm {

class Timer
{
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
        size_t m_state;
        TimerCallback m_timercallback;
        std::chrono::milliseconds m_interval;
        std::condition_variable m_condition;
        std::future<void> m_future;
};

} // namespace REDasm

#endif // TIMER_H
