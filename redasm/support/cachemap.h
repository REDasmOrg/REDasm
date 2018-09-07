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
        cache_map(): m_name(CACHE_DEFAULT), m_timestamp(time(NULL)) { }
        cache_map(const std::string& name): m_name(name), m_timestamp(time(NULL)) { }
        ~cache_map();
        iterator begin() { return iterator(*this, this->m_offsets.begin()); }
        iterator end() { return iterator(*this, this->m_offsets.end()); }
        iterator find(const T1& key) { auto it = this->m_offsets.find(key); return iterator(*this, it); }
        void commit(const T1& key, const T2& value);
        void erase(const iterator& it);
        T2 operator[](const T1& key);

    private:
        void doSerialize(const T2& value, std::fstream& fs);
        void doDeserialize(T2& value, std::fstream& fs);

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
    if(!this->m_file.is_open())
        return;

    this->m_file.close();
    std::remove(CACHE_FILE.c_str());
}

template<typename T1, typename T2> void cache_map<T1, T2>::commit(const T1& key, const T2 &value)
{
    if(!this->m_file.is_open())
    {
        this->m_file.open(CACHE_FILE, std::ios::in | std::ios::out |
                                     std::ios::trunc | std::ios::binary);

    }

    this->m_file.seekp(0, std::ios::end); // Ignore old key -> value reference, if any
    this->m_offsets[key] = this->m_file.tellp();

    this->doSerialize(value, this->m_file);
    this->m_file.clear(); // Reset error state
}

template<typename T1, typename T2> void cache_map<T1, T2>::erase(const cache_map<T1, T2>::iterator &it)
{
    auto oit = this->m_offsets.find(it.key);

    if(oit == this->m_offsets.end())
        return;

    this->m_offsets.erase(oit);
}

template<typename T1, typename T2> T2 cache_map<T1, T2>::operator[](const T1& key)
{
    auto it = this->m_offsets.find(key);

    if(it == this->m_offsets.end())
        return T2();

    T2 value;

    this->m_file.seekg(it->second, std::ios::beg);
    this->doDeserialize(value, this->m_file);
    this->m_file.clear(); // Reset error state
    return value;
}

template<typename T1, typename T2> void cache_map<T1, T2>::doSerialize(const T2& value, std::fstream& fs)
{
    std::lock_guard<std::mutex>(this->m_mutex);
    this->serialize(value, fs);
}

template<typename T1, typename T2> void cache_map<T1, T2>::doDeserialize(T2& value, std::fstream& fs)
{
    std::lock_guard<std::mutex>(this->m_mutex);
    this->deserialize(value, fs);
}

} // namespace REDasm

#endif // CACHEMAP_H
