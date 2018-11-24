#include "utils.h"
#include <algorithm>

namespace REDasm {

std::string wtoa(const std::wstring& ws)
{
    std::string s;
    std::transform(ws.begin(), ws.end(), std::back_inserter(s), [](wchar_t ch) -> char {
        return static_cast<char>(ch);
    });

    return s;
}

std::string quoted(const std::string &s) { return "\"" + s + "\""; }
std::string quoted(const char* s) { return REDasm::quoted(std::string(s)); }

std::string hexstring(const char *data, size_t size)
{
    std::stringstream ss;

    for(size_t i = 0; i < size; i++)
    {
        ss << std::uppercase <<
              std::setfill('0') <<
              std::setw(2) <<
              std::hex <<
              static_cast<size_t>(*data);
    }

   return ss.str();
}

}
