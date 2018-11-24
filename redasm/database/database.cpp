#include "database.h"
#include "database_format.h"
#include "../support/serializer.h"
#include "../disassembler/disassembler.h"
#include "../plugins/assembler/assembler.h"
#include "../plugins/format.h"
#include "../plugins/plugins.h"
#include <fstream>
#include <array>

namespace REDasm {

bool Database::save(DisassemblerAPI *disassembler, const std::string &filename)
{
    std::fstream ofs(filename, std::ios::out | std::ios::trunc);

    if(!ofs.is_open())
        return false;

    FormatPlugin* format = disassembler->format();
    ListingDocument* document = disassembler->document();
    ReferenceTable* references = disassembler->references();

    ofs.write(RDB_SIGNATURE, RDB_SIGNATURE_LENGTH);
    Serializer::serializeScalar(ofs, RDB_VERSION, sizeof(u32));
    Serializer::serializeString(ofs, format->name());
    Serializer::compressBuffer(ofs, format->buffer());
    document->serializeTo(ofs);
    references->serializeTo(ofs);

    ofs.close();
    return true;
}

DisassemblerAPI *Database::load(const std::string &filename, Buffer &buffer)
{
    std::fstream ifs(filename, std::ios::in);

    if(!ifs.is_open())
    {
        REDasm::log("Cannot open " + REDasm::quoted(filename));
        return NULL;
    }

    std::array<char, RDB_SIGNATURE_LENGTH> signature;
    ifs.read(signature.data(), RDB_SIGNATURE_LENGTH);

    if(std::strncmp(RDB_SIGNATURE, signature.data(), RDB_SIGNATURE_LENGTH))
    {
        REDasm::log("Signature check failed for " + REDasm::quoted(filename));
        return NULL;
    }

    u32 version = 0;
    Serializer::deserializeScalar(ifs, &version, sizeof(u32));

    if(version != RDB_VERSION)
    {
        REDasm::log("Invalid version, got " + std::to_string(version) + " " + std::to_string(RDB_VERSION) + " required");
        return NULL;
    }

    std::string formatname;
    Serializer::deserializeString(ifs, formatname);
    Serializer::decompressBuffer(ifs, buffer);
    std::unique_ptr<FormatPlugin> format(REDasm::getFormat(buffer));

    if(!format)
    {
        REDasm::log("Unsupported format: " + REDasm::quoted(formatname));
        return NULL;
    }

    AssemblerPlugin* assembler = REDasm::getAssembler(format->assembler());

    if(!assembler)
    {
        REDasm::log("Unsupported assembler: " + REDasm::quoted(format->assembler()));
        return NULL;
    }

    ListingDocument* document = format->document();
    document->deserializeFrom(ifs);

    Disassembler* disassembler = new Disassembler(assembler, format.release());
    ReferenceTable* references = disassembler->references();
    references->deserializeFrom(ifs);
    return disassembler;
}

} // namespace REDasm
