#ifndef DATABASE_FORMAT_H
#define DATABASE_FORMAT_H

#define RDB_SIGNATURE        "RDB"
#define RDB_SIGNATURE_LENGTH 3
#define RDB_VERSION          1

#include <string>
#include "../redasm_types.h"

namespace REDasm {

struct RDBHeader
{
    char signature[3];
    u32 version;
    std::string format, assembler;

    // InstructionPool instructions;
    // SymbolTable symboltable;
    // ReferenceTable references;
};

} // namespace REDasm

#endif // DATABASE_FORMAT_H
