#ifndef DATABASE_H
#define DATABASE_H

#include "../disassembler/disassemblerapi.h"

namespace REDasm {

class Database
{
    public:
        Database() = delete;
        Database(const Database&) = delete;
        Database& operator=(const Database&) = delete;

    public:
        static bool save(REDasm::DisassemblerAPI* disassembler, const std::string& filename);
        static REDasm::DisassemblerAPI* load(const std::string& filename);
};

} // namespace REDasm

#endif // DATABASE_H
