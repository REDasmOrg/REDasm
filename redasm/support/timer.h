#ifndef TIMER_H
#define TIMER_H

#define TIMER_DEFAULT_TIMEOUT_MS 50

#include <functional>

namespace REDasm {

class Timer
{
    private:
        Timer();

    public:
        static void tick(std::function<bool()> ontick, size_t interval = TIMER_DEFAULT_TIMEOUT_MS);
};

} // namespace REDasm

#endif // TIMER_H
