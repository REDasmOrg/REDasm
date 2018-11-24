#ifndef EVENT_H
#define EVENT_H

#include <functional>
#include <list>

namespace REDasm {

template<typename ...ARGS> struct Event
{
    typedef std::function<void(ARGS...)> HandlerType;

    Event() { }
    Event(const Event& rhs) = delete;
    Event& operator =(const Event& rhs) = delete;
    Event& operator +=(const HandlerType& handler) { m_handlers.push_back(handler); return *this; }
    void operator()(ARGS... args) const { for(HandlerType handler : m_handlers) handler(std::forward<ARGS>(args)...); }
    void removeLast() { m_handlers.pop_back(); }
    void disconnect() { m_handlers.clear(); }

    private:
        std::list<HandlerType> m_handlers;
};

typedef Event<> SimpleEvent;

}

#endif // EVENT_H
