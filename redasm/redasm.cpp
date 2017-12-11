#include "redasm.h"

namespace REDasm {

namespace Runtime {

std::string rntSearchPath;

#ifdef _WIN32
std::string rntDirSeparator = "\\";
#else
std::string rntDirSeparator = "/";
#endif

}

// namespace Runtime

} // namespace REDasm
