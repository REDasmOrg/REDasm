#ifndef DATABASE_H
#define DATABASE_H

// struct RDBHeader
// {
//     char signature[3];
//     u32 version;
//     std::string filename;          // XORified
//     std::string format;
//     std::string assembler;
//
//     Buffer buffer;                 // ZLib compressed stream
//     InstructionCache instructions;
//     SymbolTable symboltable;
//     ReferenceTable references;
// };

#define RDB_SIGNATURE        "RDB"
#define RDB_SIGNATURE_EXT    "rdb"
#define RDB_SIGNATURE_LENGTH 3
#define RDB_VERSION          1

#include "../disassembler/disassembler.h"

namespace REDasm {

class Database
{
    public:
        Database() = delete;
        Database(const Database&) = delete;
        Database& operator=(const Database&) = delete;

    public:
        static const std::string& lastError();
        static bool save(REDasm::DisassemblerAPI* disassembler, const std::string& dbfilename, const std::string& filename);
        static REDasm::Disassembler* load(const std::string& dbfilename, std::string& filename, Buffer& buffer);

    private:
        static std::string m_lasterror;
};

} // namespace REDasm

#endif // DATABASE_H
