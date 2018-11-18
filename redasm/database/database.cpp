#include "database.h"
#include "database_format.h"
#include "../support/serializer.h"
#include "../plugins/assembler/assembler.h"
#include "../plugins/format.h"
#include <fstream>

namespace REDasm {

bool Database::save(DisassemblerAPI *disassembler, const std::string &filename)
{
    std::fstream ofs(filename, std::ios::out | std::ios::trunc);

    if(!ofs.is_open())
        return false;

    FormatPlugin* format = disassembler->format();
    AssemblerPlugin* assembler = disassembler->assembler();
    ListingDocument* document = disassembler->document();
    ReferenceTable* references = disassembler->references();
    InstructionPool* instructions = document->instructions();
    SymbolTable* symbols = document->symbols();

    ofs.write(RDB_SIGNATURE, RDB_SIGNATURE_LENGTH);
    Serializer::serializeScalar(ofs, RDB_VERSION, sizeof(u32));
    Serializer::serializeString(ofs, format->name());
    Serializer::serializeString(ofs, assembler->name());

    instructions->serializeTo(ofs);
    symbols->serializeTo(ofs);
    references->serializeTo(ofs);

    ofs.close();
    return true;
}

DisassemblerAPI *Database::load(const std::string &filename)
{
    return NULL;
}

} // namespace REDasm
