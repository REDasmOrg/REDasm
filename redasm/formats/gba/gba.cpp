#include "gba.h"
#include "gba_analyzer.h"
#include <cstring>

// https://www.reinterpretcast.com/writing-a-game-boy-advance-game

#define GBA_EWRAM_START_ADDR   0x02000000
#define GBA_EWRAM_SIZE         0x00030000

#define GBA_IWRAM_START_ADDR   0x03000000
#define GBA_IWRAM_SIZE         0x00007FFF

#define GBA_IOREG_START_ADDR   0x04000000
#define GBA_IOREG_SIZE         0x000003FF

#define GBA_PALETTE_START_ADDR 0x05000000
#define GBA_PALETTE_SIZE       0x000003FF

#define GBA_VRAM_START_ADDR    0x06000000
#define GBA_VRAM_SIZE          0x00017FFF

#define GBA_OAM_START_ADDR     0x07000000
#define GBA_OAM_SIZE           0x000003FF

#define GBA_ROM_START_ADDR     0x08000000
#define GBA_ROM_SIZE           0x02000000

#define GBA_SEGMENT_AREA(name) GBA_##name##_START_ADDR, GBA_##name##_SIZE

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
    return "metaarm";
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

    this->defineSegment("EWRAM", 0, GBA_SEGMENT_AREA(EWRAM), SegmentTypes::Bss);
    this->defineSegment("IWRAM", 0, GBA_SEGMENT_AREA(IWRAM), SegmentTypes::Bss);
    this->defineSegment("IOREG", 0, GBA_SEGMENT_AREA(IOREG), SegmentTypes::Bss);
    this->defineSegment("PALETTE", 0, GBA_SEGMENT_AREA(PALETTE), SegmentTypes::Bss);
    this->defineSegment("VRAM", 0, GBA_SEGMENT_AREA(VRAM), SegmentTypes::Bss);
    this->defineSegment("OAM", 0, GBA_SEGMENT_AREA(OAM), SegmentTypes::Bss);
    this->defineSegment("ROM", 0, GBA_ROM_START_ADDR, length, SegmentTypes::Code | SegmentTypes::Data);

    this->defineEntryPoint(GBA_ROM_START_ADDR); // Let REDasm decode and follow the "EP Field"
    FormatPluginT<GbaRomHeader>::load(rawformat);
    return true;
}

}
