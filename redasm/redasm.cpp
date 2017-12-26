#include "redasm.h"
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

namespace OperandSizes {

std::string size(u32 opsize)
{
    if(opsize == OperandSizes::Byte)
        return "byte";

    if(opsize == OperandSizes::Word)
        return "word";

    if(opsize == OperandSizes::Dword)
        return "dword";

    if(opsize == OperandSizes::Qword)
        return "qword";

    return std::string();
}

} // naspace OperandSizes

} // namespace REDasm
