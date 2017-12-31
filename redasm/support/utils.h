#ifndef UTILS_H
#define UTILS_H

#include <sstream>
#include <string>
#include <iomanip>
#include "demangler.h"

namespace REDasm
{

std::string normalize(std::string s);
std::string quoted(const std::string& s);
std::string wtoa(const std::wstring& wide);

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

template<typename T> std::string hex(T t, int bits = 0, bool withprefix = true)
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

template<typename T> std::string symbol(const std::string& prefix, T t)
{
    std::stringstream ss;
    ss << prefix << "_" << std::hex << t;
    return ss.str();
}

}

#endif // UTILS_H
