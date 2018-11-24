#include "database.h"
#include "../support/serializer.h"
#include "../plugins/assembler/assembler.h"
#include "../plugins/format.h"
#include "../plugins/plugins.h"
#include <fstream>
#include <array>

namespace REDasm {

std::string Database::m_lasterror;

bool Database::save(DisassemblerAPI *disassembler, const std::string &filename)
{
    m_lasterror.clear();
    std::fstream ofs(filename, std::ios::out | std::ios::trunc);

    if(!ofs.is_open())
    {
        m_lasterror = "Cannot save " + REDasm::quoted(filename);
        return false;
    }

    FormatPlugin* format = disassembler->format();
    ListingDocument* document = disassembler->document();
    ReferenceTable* references = disassembler->references();

    ofs.write(RDB_SIGNATURE, RDB_SIGNATURE_LENGTH);
    Serializer::serializeScalar(ofs, RDB_VERSION, sizeof(u32));
    Serializer::serializeString(ofs, format->name());

    if(!Serializer::compressBuffer(ofs, format->buffer()))
    {
        m_lasterror = "Cannot compress database " + REDasm::quoted(filename);
        return false;
    }

    document->serializeTo(ofs);
    references->serializeTo(ofs);
    return true;
}

Disassembler *Database::load(const std::string &filename, Buffer &buffer)
{
    m_lasterror.clear();
    std::fstream ifs(filename, std::ios::in);

    if(!ifs.is_open())
    {
        m_lasterror = "Cannot open " + REDasm::quoted(filename);
        return NULL;
    }

    std::array<char, RDB_SIGNATURE_LENGTH> signature;
    ifs.read(signature.data(), RDB_SIGNATURE_LENGTH);

    if(std::strncmp(RDB_SIGNATURE, signature.data(), RDB_SIGNATURE_LENGTH))
    {
        m_lasterror = "Signature check failed for " + REDasm::quoted(filename);
        return NULL;
    }

    u32 version = 0;
    Serializer::deserializeScalar(ifs, &version, sizeof(u32));

    if(version != RDB_VERSION)
    {
        m_lasterror = "Invalid version, got " + std::to_string(version) + " " + std::to_string(RDB_VERSION) + " required";
        return NULL;
    }

    std::string formatname;
    Serializer::deserializeString(ifs, formatname);

    if(!Serializer::decompressBuffer(ifs, buffer))
    {
        m_lasterror = "Cannot decompress database " + REDasm::quoted(filename);
        return NULL;
    }

    std::unique_ptr<FormatPlugin> format(REDasm::getFormat(buffer));

    if(!format)
    {
        m_lasterror = "Unsupported format: " + REDasm::quoted(formatname);
        return NULL;
    }

    AssemblerPlugin* assembler = REDasm::getAssembler(format->assembler());

    if(!assembler)
    {
        m_lasterror = "Unsupported assembler: " + REDasm::quoted(format->assembler());
        return NULL;
    }

    ListingDocument* document = format->document();
    document->deserializeFrom(ifs);

    Disassembler* disassembler = new Disassembler(assembler, format.release());
    ReferenceTable* references = disassembler->references();
    references->deserializeFrom(ifs);
    return disassembler;
}

const std::string &Database::lastError() { return m_lasterror; }

} // namespace REDasm
