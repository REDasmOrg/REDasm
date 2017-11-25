#include "utils.h"
#include <algorithm>

namespace REDasm {

std::string normalize(std::string s)
{
    std::replace(s.begin(), s.end(), '.', '_');
    std::replace(s.begin(), s.end(), ' ', '_');
    return s;
}

std::string wtoa(const std::wstring& ws)
{
    std::string s;
    std::transform(ws.begin(), ws.end(), std::back_inserter(s), [](wchar_t ch) -> char {
        return static_cast<char>(ch);
    });

    return s;
}

}
