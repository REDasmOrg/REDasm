#include "binary.h"

namespace REDasm {

BinaryFormat::BinaryFormat(): FormatPluginB(), m_bits(0) {  }
const char *BinaryFormat::name() const { return "Binary Format"; }
const char *BinaryFormat::assembler() const { return m_assembler.c_str(); }
u32 BinaryFormat::bits() const { return m_bits; }
u32 BinaryFormat::flags() const { return FormatFlags::Binary; }

bool BinaryFormat::load(u8 *rawformat, u64)
{
    FormatPluginB::load(rawformat);
    return true;
}

void BinaryFormat::build(const std::string &assembler, u32 bits, offset_t offset, address_t baseaddress, address_t entrypoint, u64 size)
{
    m_assembler = assembler;
    m_bits = bits;

    m_document.segment("seg000", offset, baseaddress, size, SegmentTypes::Code | SegmentTypes::Data);
    m_document.entry(entrypoint);
}

} // namespace REDasm
