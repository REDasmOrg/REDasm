#include "cachemap.h"
#include <ios>

namespace REDasm {

template<typename T1, typename T2> cache_map<T1, T2>::cache_map(): m_name(CACHE_DEFAULT), m_timestamp(time(NULL))
{
    m_file.exceptions(std::fstream::failbit);
}

template<typename T1, typename T2> cache_map<T1, T2>::cache_map(const std::string &name) : m_name(name), m_timestamp(time(NULL))
{
    m_file.open(CACHE_FILE, std::ios::in | std::ios::out | std::ios::trunc | std::ios::binary);
}

template<typename T1, typename T2> cache_map<T1, T2>::~cache_map()
{
    if(!m_file.is_open())
        return;

    m_file.close();
    std::remove(CACHE_FILE.c_str());
}

template<typename T1, typename T2> u64 cache_map<T1, T2>::size() const { return m_offsets.size(); }

template<typename T1, typename T2> void cache_map<T1, T2>::commit(const T1& key, const T2 &value)
{
    io_lock lock(m_mutex);

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

template<typename T1, typename T2> T2 cache_map<T1, T2>::value(const T1 &key)
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

template<typename T1, typename T2> T2 cache_map<T1, T2>::operator[](const T1& key) { return this->value(key); }

template<typename T1, typename T2> void cache_map<T1, T2>::serializeTo(std::fstream &fs)
{
    Serializer::serializeScalar(fs, static_cast<u64>(this->size()));

    for(auto it = this->begin(); it != this->end(); it++)
    {
        Serializer::serializeScalar(fs, it.key);
        this->serialize(*it, fs);
    }
}

template<typename T1, typename T2> void cache_map<T1, T2>::deserializeFrom(std::fstream &fs)
{
    u64 count = 0;
    Serializer::deserializeScalar(fs, &count);

    for(u64 i = 0; i < count; i++)
    {
        T1 t1;
        T2 t2;

        Serializer::deserializeScalar(fs, &t1);
        this->deserialize(t2, fs);
        this->commit(t1, t2); // Rebuild cache

        deserialized(t2);
    }
}

} // namespace REDasm
