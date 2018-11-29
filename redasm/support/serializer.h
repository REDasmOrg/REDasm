#ifndef SERIALIZER_H
#define SERIALIZER_H

#include <fstream>
#include <algorithm>
#include <functional>
#include "../redasm_buffer.h"

namespace REDasm {
namespace Serializer {

class Serializable
{
    public:
        virtual void serializeTo(std::fstream& fs) = 0;
        virtual void deserializeFrom(std::fstream& fs) = 0;
};

template<typename T> void serializeScalar(std::fstream& fs, T scalar, u64 size = sizeof(T)) { fs.write(reinterpret_cast<const char*>(&scalar), size); }
template<typename T> void deserializeScalar(std::fstream& fs, T* scalar, u64 size = sizeof(T)) { fs.read(reinterpret_cast<char*>(scalar), size); }

template<template<typename, typename> class V, typename T> void serializeArray(std::fstream& fs, const V< T, std::allocator<T> >& v, std::function<void(const T&)> cb) {
    Serializer::serializeScalar(fs, v.size(), sizeof(u32));
    std::for_each(v.begin(), v.end(), cb);
}

template<template<typename, typename, typename> class V, typename T> void serializeArray(std::fstream& fs, const V< T, std::less<T>, std::allocator<T> >& v, std::function<void(const T&)> cb) {
    Serializer::serializeScalar(fs, v.size(), sizeof(u32));
    std::for_each(v.begin(), v.end(), cb);
}

template<template<typename, typename> class V, typename T> void deserializeArray(std::fstream& fs, V< T, std::allocator<T> >& v, std::function<void(T&)> cb) {

    u32 size = 0;
    Serializer::deserializeScalar(fs, &size, sizeof(u32));

    for(u32 i = 0; i < size; i++) {
        T t;
        cb(t);
        v.push_back(t);
    }
}

template<template<typename, typename, typename> class V, typename T> void deserializeArray(std::fstream& fs, V< T, std::less<T>, std::allocator<T> >& v, std::function<void(T&)> cb) {

    u32 size = 0;
    Serializer::deserializeScalar(fs, &size, sizeof(u32));

    for(u32 i = 0; i < size; i++) {
        T t;
        cb(t);
        v.insert(t);
    }
}

void obfuscateString(std::fstream& fs, std::string s);
void deobfuscateString(std::fstream& fs, std::string& s);
bool compressBuffer(std::fstream& fs, Buffer &b);
bool decompressBuffer(std::fstream& fs, Buffer& cb);

void serializeBuffer(std::fstream& fs, const Buffer& b);
void deserializeBuffer(std::fstream& fs, Buffer& b);
void serializeString(std::fstream& fs, const std::string& s);
void deserializeString(std::fstream& fs, std::string& s);

} // namespace Serializer
} // namespace REDasm

#endif // SERIALIZER_H
