#include "timer.h"
#include <thread>
#include <mutex>

namespace REDasm {

Timer::Timer() { }

void Timer::tick(std::function<bool()> ontick, size_t interval)
{
    std::thread([ontick, interval]() {
        std::mutex m;
        bool res = true;

        do {
            std::this_thread::sleep_for(std::chrono::milliseconds(interval));
            std::lock_guard<std::mutex> lock(m);
            res = ontick();
        }
        while(res);

    }).detach();
}

} // namespace REDasm
