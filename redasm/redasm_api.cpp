#include "redasm_api.h"
#include <iostream>

namespace REDasm {

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
