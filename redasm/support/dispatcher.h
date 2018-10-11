#ifndef DISPATCHER_H
#define DISPATCHER_H

#include <unordered_map>
#include <functional>

template<typename KEY, typename... ARGS> class Dispatcher: protected std::unordered_map<KEY, std::function<void(ARGS...)> >
{
    public:
        typedef std::function<void(ARGS...)> DispatcherType;
        typedef std::unordered_map<KEY, DispatcherType> Type;

    public:
        using Type::operator[];
        using Type::empty;
        using Type::size;

    public:
        Dispatcher(): Type() { }

        void operator()(KEY key, ARGS... args) {
            auto it = this->find(key);

            if(it != this->end())
                it->second(std::forward<ARGS>(args)...);
        }
};

#endif // DISPATCHER_H
