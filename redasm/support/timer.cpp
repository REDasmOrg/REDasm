#include "timer.h"
#include <thread>

namespace REDasm {

Timer::Timer() { }

void Timer::tick(std::function<bool()> ontick, size_t interval)
{
    std::thread([ontick, interval]() {
        bool res = true;

        do {
            res = ontick();
            std::this_thread::sleep_for(std::chrono::milliseconds(interval));
        }
        while(res);

    }).detach();
}

} // namespace REDasm
