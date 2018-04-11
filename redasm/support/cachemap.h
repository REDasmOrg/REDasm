#ifndef CACHEMAP_H
#define CACHEMAP_H

#define CACHE_DEFAULT  "cachemap"
#define CACHE_FILE_EXT ".db"
#define CACHE_FILE     (_name + "_" + std::to_string(_timestamp) + CACHE_FILE_EXT)

#include <functional>
#include <iostream>
#include <map>
#include <cstdio>
#include <fstream>
#include "../redasm.h"

namespace REDasm {

template<typename T1, typename T2> class cache_map // Use STL's coding style for this type
{
    private:
        typedef cache_map<T1, T2> type;
        typedef std::map<T1, offset_t> offset_map;
        typedef typename offset_map::iterator offset_iterator;

    public:
        class iterator: public std::iterator<std::random_access_iterator_tag, T2> {
            public:
                explicit iterator(type& container, const offset_iterator& offit): _container(container), _offit(offit), key(offit->first) { }
                iterator& operator++() { _offit++; update(); return *this; }
                iterator& operator--() { _offit--; update(); return *this; }
                iterator operator++(int) { iterator copy = *this; _offit++; update(); return copy; }
                iterator operator--(int) { iterator copy = *this; _offit--; update(); return copy; }
                bool operator==(const iterator& rhs) const { return _offit == rhs._offit; }
                bool operator!=(const iterator& rhs) const { return _offit != rhs._offit; }
                iterator& operator=(const iterator& rhs) { _offit = rhs._offit; update(); return *this; }
                T2 operator *() { return _container[key]; }

            private:
                void update() { key = _offit->first; }

            private:
                type& _container;
                offset_iterator _offit;

            public:
                T1 key;
        };

    public:
        cache_map(): _name(CACHE_DEFAULT), _timestamp(time(NULL)) { }
        cache_map(const std::string& name): _name(name), _timestamp(time(NULL)) { }
        ~cache_map();
        iterator begin() { return iterator(*this, this->_offsets.begin()); }
        iterator end() { return iterator(*this, this->_offsets.end()); }
        iterator find(const T1& key) { auto it = this->_offsets.find(key); return iterator(*this, it); }
        void commit(const T1& key, const T2& value);
        void erase(const iterator& it);
        T2 operator[](const T1& key);

    protected:
        virtual void serialize(const T2& value, std::fstream& fs) = 0;
        virtual void deserialize(T2& value, std::fstream& fs) = 0;

    private:
        std::string _name;
        offset_map _offsets;
        std::fstream _file;
        time_t _timestamp;
};

template<typename T1, typename T2> cache_map<T1, T2>::~cache_map()
{
    if(!this->_file.is_open())
        return;

    this->_file.close();
    std::remove(CACHE_FILE.c_str());
}

template<typename T1, typename T2> void cache_map<T1, T2>::commit(const T1& key, const T2 &value)
{
    if(!this->_file.is_open())
    {
        this->_file.open(CACHE_FILE, std::ios::in | std::ios::out |
                                     std::ios::trunc | std::ios::binary);

    }

    this->_file.seekp(0, std::ios::end); // Ignore old key -> value reference, if any
    this->_offsets[key] = this->_file.tellp();

    this->serialize(value, this->_file);
    this->_file.clear(); // Reset error state
}

template<typename T1, typename T2> void cache_map<T1, T2>::erase(const cache_map<T1, T2>::iterator &it)
{
    auto oit = this->_offsets.find(it.key);

    if(oit == this->_offsets.end())
        return;

    this->_offsets.erase(oit);
}

template<typename T1, typename T2> T2 cache_map<T1, T2>::operator[](const T1& key)
{
    auto it = this->_offsets.find(key);

    if(it == this->_offsets.end())
        return T2();

    T2 value;

    this->_file.seekg(it->second, std::ios::beg);
    this->deserialize(value, this->_file);
    this->_file.clear(); // Reset error state
    return value;
}

} // namespace REDasm

#endif // CACHEMAP_H
