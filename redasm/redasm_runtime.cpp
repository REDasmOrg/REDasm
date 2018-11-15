#include "redasm_runtime.h"
#include <iostream>

namespace REDasm {
namespace Runtime {

std::string rntSearchPath;

#ifdef _WIN32
std::string rntDirSeparator = "\\";
#else
std::string rntDirSeparator = "/";
#endif

LogCallback rntLogCallback = [](const std::string& s) { std::cout << s << std::endl; };
LogCallback rntStatusCallback = [](const std::string&) { };

} // namespace Runtime
} // namespace REDasm
