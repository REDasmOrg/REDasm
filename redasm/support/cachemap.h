#ifndef CACHEMAP_H
#define CACHEMAP_H

#define CACHE_DEFAULT  "cachemap"
#define CACHE_FILE_EXT ".db"
#define CACHE_FILE     (_name + CACHE_FILE_EXT)

#include <map>
#include <iostream>
#include <cstdio>
#include <fstream>
#include "../redasm.h"

namespace REDasm {

namespace Serializer {

void serialize(std::fstream& fs, const std::string& s);
void deserialize(std::fstream& fs, std::string& s);

} // namespace Serializer

template<typename T1, typename T2> class CacheMap
{
    private:
        typedef std::map<T1, offset_t> OffsetMap;

    public:
        typedef typename OffsetMap::iterator iterator;

    public:
        CacheMap();
        ~CacheMap();
        CacheMap::iterator begin() { return this->_offsets.begin(); }
        CacheMap::iterator end() { return this->_offsets.end(); }
        void setName(const std::string& name) { this->_name = name; }
        bool contains(const T1& key) const { return this->_offsets.find(key) != this->_offsets.end(); }
        void commit(const T1& key, const T2& value);
        bool get(const T1& key, T2& value);
        void erase(const T1& key);

    protected:
        virtual void serialize(const T2& value, std::fstream& fs) = 0;
        virtual void deserialize(T2& value, std::fstream& fs) = 0;

    private:
        std::string _name;
        OffsetMap _offsets;
        std::fstream _file;
};

template<typename T1, typename T2> CacheMap<T1, T2>::CacheMap(): _name(CACHE_DEFAULT)
{
}

template<typename T1, typename T2> CacheMap<T1, T2>::~CacheMap()
{
    if(!this->_file.is_open())
        return;

    this->_file.close();
    std::remove(CACHE_FILE.c_str());
}

template<typename T1, typename T2> void CacheMap<T1, T2>::commit(const T1& key, const T2 &value)
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

template<typename T1, typename T2> bool CacheMap<T1, T2>::get(const T1& key, T2 &value)
{
    if(!this->_file.is_open())
        return false;

    auto it = this->_offsets.find(key);

    if(it == this->_offsets.end())
        return false;

    this->_file.seekg(it->second, std::ios::beg);
    this->deserialize(value, this->_file);
    this->_file.clear(); // Reset error state
    return true;
}

template<typename T1, typename T2> void CacheMap<T1, T2>::erase(const T1& key)
{
    auto it = this->_offsets.find(key);

    if(it == this->_offsets.end())
        return;

    this->_offsets.erase(it);
}

} // namespace REDasm

#endif // CACHEMAP_H
