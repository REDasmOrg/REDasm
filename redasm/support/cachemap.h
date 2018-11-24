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
#include "../support/serializer.h"
#include "../redasm_types.h"
#include "event.h"

namespace REDasm {

template<typename T1, typename T2> class cache_map: public Serializer::Serializable // Use STL's coding style for this type
{
    using io_lock = std::unique_lock<std::mutex>;

    private:
        typedef cache_map<T1, T2> type;
        typedef std::map<T1, offset_t> offset_map;
        typedef typename offset_map::iterator offset_iterator;

    public:
        Event<const T2&> deserialized;

    public:
        class iterator: public std::iterator<std::random_access_iterator_tag, T2> {
            public:
                explicit iterator(type& container, const offset_iterator& offit): m_container(container), m_offit(offit) { update(); }
                iterator& operator++() { m_offit++; update(); return *this; }
                iterator& operator--() { m_offit--; update(); return *this; }
                iterator operator++(int) { iterator copy = *this; m_offit++; update(); return copy; }
                iterator operator--(int) { iterator copy = *this; m_offit--; update(); return copy; }
                bool operator==(const iterator& rhs) const { return m_offit == rhs.m_offit; }
                bool operator!=(const iterator& rhs) const { return m_offit != rhs.m_offit; }
                iterator& operator=(const iterator& rhs) { m_offit = rhs.m_offit; update(); return *this; }
                T2 operator *() { return m_container[key]; }

            private:
                void update() { if(m_offit != m_container.m_offsets.end()) key = m_offit->first; }

            private:
                type& m_container;
                offset_iterator m_offit;

            public:
                T1 key;
        };

    public:
        cache_map();
        cache_map(const std::string& name);
        virtual ~cache_map();
        iterator begin() { return iterator(*this, m_offsets.begin()); }
        iterator end() { return iterator(*this, m_offsets.end()); }
        iterator find(const T1& key) { auto it = m_offsets.find(key); return (it != m_offsets.end() ? iterator(*this, it) : this->end()); }
        u64 size() const;
        void commit(const T1& key, const T2& value);
        void erase(const iterator& it);
        T2 value(const T1& key);
        T2 operator[](const T1& key);
        virtual void serializeTo(std::fstream& fs);
        virtual void deserializeFrom(std::fstream& fs);

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

} // namespace REDasm

#include "cachemap.cpp"

#endif // CACHEMAP_H
