#ifndef CACHEMAP_H
#define CACHEMAP_H

#define CACHE_DEFAULT  "cachemap"
#define CACHE_FILE_EXT ".db"
#define CACHE_FILE     (m_name + "_" + std::to_string(m_timestamp) + CACHE_FILE_EXT)

#include <functional>
#include <iostream>
#include <map>
#include <cstdio>
#include <fstream>
#include <mutex>
#include "../redasm.h"

namespace REDasm {

template<typename T1, typename T2> class cache_map // Use STL's coding style for this type
{
    using io_lock = std::unique_lock<std::mutex>;

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
        cache_map(): m_name(CACHE_DEFAULT), m_timestamp(time(NULL)) { m_file.exceptions(std::fstream::failbit); }
        cache_map(const std::string& name): m_name(name), m_timestamp(time(NULL)) { }
        ~cache_map();
        iterator begin() { return iterator(*this, m_offsets.begin()); }
        iterator end() { return iterator(*this, m_offsets.end()); }
        iterator find(const T1& key) { auto it = m_offsets.find(key); return iterator(*this, it); }
        void commit(const T1& key, const T2& value);
        void erase(const iterator& it);
        T2 operator[](const T1& key);

    protected:
        virtual void serialize(const T2& value, std::fstream& fs) = 0;
        virtual void deserialize(T2& value, std::fstream& fs) = 0;

    private:
        std::mutex m_mutex;
        std::string m_name;
        offset_map m_offsets;
        std::fstream m_file;
        time_t m_timestamp;
};

template<typename T1, typename T2> cache_map<T1, T2>::~cache_map()
{
    if(!m_file.is_open())
        return;

    m_file.close();
    std::remove(CACHE_FILE.c_str());
}

template<typename T1, typename T2> void cache_map<T1, T2>::commit(const T1& key, const T2 &value)
{
    io_lock lock(m_mutex);

    if(!m_file.is_open())
    {
        m_file.open(CACHE_FILE, std::ios::in | std::ios::out |
                                     std::ios::trunc | std::ios::binary);

    }

    m_file.seekp(0, std::ios::end); // Ignore old key -> value reference, if any
    m_offsets[key] = m_file.tellp();
    this->serialize(value, m_file);
}

template<typename T1, typename T2> void cache_map<T1, T2>::erase(const cache_map<T1, T2>::iterator &it)
{
    io_lock lock(m_mutex);
    auto oit = m_offsets.find(it.key);

    if(oit == m_offsets.end())
        return;

    m_offsets.erase(oit);
}

template<typename T1, typename T2> T2 cache_map<T1, T2>::operator[](const T1& key)
{
    io_lock lock(m_mutex);
    auto it = m_offsets.find(key);

    if(it == m_offsets.end())
        return T2();

    T2 value;

    m_file.seekg(it->second, std::ios::beg);
    this->deserialize(value, m_file);
    return value;
}

} // namespace REDasm

#endif // CACHEMAP_H
