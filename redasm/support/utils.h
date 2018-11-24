#ifndef UTILS_H
#define UTILS_H

#include <sstream>
#include <string>
#include <iomanip>
#include <climits>
#include "demangler.h"

namespace REDasm
{
std::string quoted(const std::string& s);
std::string wtoa(const std::wstring& wide);
std::string quoted(const char* s);
std::string hexstring(const char* data, size_t size);

template<typename T> struct bitwidth { static const size_t value = sizeof(T) * CHAR_BIT; };

inline std::string trampoline(const std::string& s) { return "_" + s; }
template<typename T> inline std::string quoted(T t) { return REDasm::quoted(std::to_string(t)); }
template<typename T, typename U> inline T* relpointer(U* base, size_t offset) { return reinterpret_cast<T*>(reinterpret_cast<size_t>(base) + offset); }

template<typename T, typename U> inline T readpointer(U** p)
{
    T v = *reinterpret_cast<T*>(*p);
    *p = REDasm::relpointer<U>(*p, sizeof(T));
    return v;
}

template<typename T, typename U> T aligned(T t, U a)
{
    T r = t % a;
    return r ? (t + (a - r)) : t;
}

template<typename T> std::string wtoa(T* ws, size_t len)
{
    std::string s;
    char* p = reinterpret_cast<char*>(ws);

    for(size_t i = 0; i < len; i++, p += sizeof(char) * 2)
        s += *p;

    return s;
}

template<typename T> std::string dec(T t)
{
    std::stringstream ss;
    ss << t;
    return ss.str();
}

template<typename T> std::string hex(T t, unsigned int bits = 0, bool withprefix = false)
{
    std::stringstream ss;

    if(withprefix && (t > 9))
        ss << "0x";

    ss << std::uppercase << std::hex;

    if(bits > 0)
        ss << std::setfill('0') << std::setw(bits / 4);

    if(std::is_signed<T>::value && t < 0)
        ss << "-" << (~t) + 1;
    else
        ss << t;

    return ss.str();
}

}

#endif // UTILS_H
