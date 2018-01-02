#include "binary.h"

namespace REDasm {

BinaryFormat::BinaryFormat(): FormatPluginB(), _bits(0)
{

}

const char *BinaryFormat::name() const
{
    return "Binary Format";
}

const char *BinaryFormat::assembler() const
{
    return this->_assembler.c_str();
}

u32 BinaryFormat::bits() const
{
    return this->_bits;
}

bool BinaryFormat::load(u8 *rawformat)
{
    FormatPluginB::load(rawformat);
    return true;
}

bool BinaryFormat::isBinary() const
{
    return true;
}

void BinaryFormat::build(const std::string &assembler, u32 bits, offset_t offset, address_t baseaddress, address_t entry, u64 size)
{
    this->_assembler = assembler;
    this->_bits = bits;

    this->defineSegment("seg000", offset, baseaddress, size, SegmentTypes::Code | SegmentTypes::Data);
    this->defineEntryPoint(entry);
}

} // namespace REDasm
