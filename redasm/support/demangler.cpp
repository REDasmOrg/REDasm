#include "demangler.h"

#ifdef __GNUC__
#include <cstdlib>
#include <cxxabi.h>
#endif

namespace REDasm {

std::string demangle(const std::string &s)
{
#ifdef __GNUC__
    int status = 0;
    char* ret = abi::__cxa_demangle(s.c_str(), NULL, NULL, &status);

    if(!ret)
        return s;

    std::string demangled(ret);
    std::free(ret);
    return demangled;
#else
    return s;
#endif
}

}
