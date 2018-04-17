#include "gba.h"
#include "gba_analyzer.h"
#include <cstring>

#define GBAEWRAM_START_ADDR  0x02000000
#define GBA_EWROM_SIZE       0x00030000

#define GBA_IWRAM_START_ADDR 0x03000000
#define GBA_IWRAM_SIZE       0x00007FFF

#define GBA_ROM_START_ADDR   0x08000000
#define GBA_ROM_SIZE         0x02000000

namespace REDasm {

GbaRomFormat::GbaRomFormat(): FormatPluginT<GbaRomHeader>()
{

}

const char *GbaRomFormat::name() const
{
    return "Game Boy Advance ROM";
}

u32 GbaRomFormat::bits() const
{
    return 32;
}

u32 GbaRomFormat::flags() const
{
    return FormatFlags::IgnoreUnexploredCode;
}

const char *GbaRomFormat::assembler() const
{
    return "arm"; //"arm7tdmi";
}

Analyzer *GbaRomFormat::createAnalyzer(DisassemblerAPI *disassembler, const SignatureFiles &signatures) const
{
    return new GbaAnalyzer(disassembler, signatures);
}

bool GbaRomFormat::load(u8* rawformat, u64 length)
{
    GbaRomHeader* format = convert(rawformat);

    if(!(format->fixed_val == 0x96)) // no signature/magic number is present in GBA ROMS
        return false;

    this->defineSegment("EWRAM", 0, GBAEWRAM_START_ADDR, GBA_EWROM_SIZE, SegmentTypes::Bss);
    this->defineSegment("IWRAM", 0, GBA_IWRAM_START_ADDR, GBA_IWRAM_SIZE, SegmentTypes::Bss);
    this->defineSegment("ROM", 0, GBA_ROM_START_ADDR, length, SegmentTypes::Code | SegmentTypes::Data);

    this->defineEntryPoint(GBA_ROM_START_ADDR); // Let REDasm decode and follow the "EP Field"
    FormatPluginT<GbaRomHeader>::load(rawformat);
    return true;
}

}
