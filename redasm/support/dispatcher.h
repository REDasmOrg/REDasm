#ifndef DISPATCHER_H
#define DISPATCHER_H

#include <unordered_map>
#include <functional>

template<typename KEY, typename SIGNATURE> class Dispatcher: protected std::unordered_map<KEY, std::function<SIGNATURE> >
{
    public:
        typedef std::function<SIGNATURE> DispatcherType;
        typedef std::unordered_map<KEY, DispatcherType> Type;

    public:
        using Type::operator[];
        using Type::empty;
        using Type::size;

    public:
        Dispatcher(): Type() { }
        bool contains(KEY key) const { return this->find(key) != this->end(); }

        typename DispatcherType::result_type operator()(KEY key, typename DispatcherType::argument_type args) {
            auto it = this->find(key);

            if(it != this->end())
                return it->second(args);

            return typename DispatcherType::result_type();
        }
};

#endif // DISPATCHER_H
