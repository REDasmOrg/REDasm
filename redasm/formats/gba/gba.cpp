#include "gba.h"
#include "gba_analyzer.h"
#include <cstring>
#include <cctype>

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

GbaRomFormat::GbaRomFormat(): FormatPluginT<GbaRomHeader>() { }
const char *GbaRomFormat::name() const { return "Game Boy Advance ROM"; }
u32 GbaRomFormat::bits() const { return 32; }
u32 GbaRomFormat::flags() const { return FormatFlags::IgnoreUnexploredCode; }
const char *GbaRomFormat::assembler() const { return "metaarm"; }

Analyzer *GbaRomFormat::createAnalyzer(DisassemblerAPI *disassembler, const SignatureFiles &signatures) const
{
    return new GbaAnalyzer(disassembler, signatures);
}

bool GbaRomFormat::load(u8* rawformat, u64 length)
{
    GbaRomHeader* format = convert(rawformat);

    if(!this->validateRom(format, length))
        return false;

    m_document.segment("EWRAM", 0, GBA_SEGMENT_AREA(EWRAM), SegmentTypes::Bss);
    m_document.segment("IWRAM", 0, GBA_SEGMENT_AREA(IWRAM), SegmentTypes::Bss);
    m_document.segment("IOREG", 0, GBA_SEGMENT_AREA(IOREG), SegmentTypes::Bss);
    m_document.segment("PALETTE", 0, GBA_SEGMENT_AREA(PALETTE), SegmentTypes::Bss);
    m_document.segment("VRAM", 0, GBA_SEGMENT_AREA(VRAM), SegmentTypes::Bss);
    m_document.segment("OAM", 0, GBA_SEGMENT_AREA(OAM), SegmentTypes::Bss);
    m_document.segment("ROM", 0, GBA_ROM_START_ADDR, length, SegmentTypes::Code | SegmentTypes::Data);

    m_document.entry(GBA_ROM_START_ADDR); // Let REDasm decode and follow the "EP Field"
    FormatPluginT<GbaRomHeader>::load(rawformat);
    return true;
}

bool GbaRomFormat::isUppercaseAscii(const char *s, size_t c)
{
    for(size_t i = 0; i < c; i++)
    {
        if(std::isupper(s[i]) || std::ispunct(s[i]) || std::isdigit(s[i]))
            continue;

        if(!s[i] && i) // Reached '\0'
            break;

        return false;
    }

    return true;
}

u8 GbaRomFormat::calculateChecksum(GbaRomHeader *gbaheader)
{
    u8* header = reinterpret_cast<u8*>(gbaheader);
    u8 checksum = 0;

    for(size_t i = 0xA0; i <= 0xBC; i++)
        checksum -= header[i];

    return checksum - 0x19;
}

bool GbaRomFormat::validateRom(GbaRomHeader *gbaheader, u64 length)
{
    if((gbaheader->fixed_val != 0x96) || (length < GBA_ROM_HEADER_SIZE))
        return false;

    if(!GbaRomFormat::isUppercaseAscii(gbaheader->game_title, GBA_GAME_TITLE_SIZE))
        return false;

    if(!GbaRomFormat::isUppercaseAscii(gbaheader->game_code, GBA_GAME_CODE_SIZE))
        return false;

    if(!GbaRomFormat::isUppercaseAscii(gbaheader->maker_code, GBA_MAKER_CODE_SIZE))
        return false;

    return gbaheader->header_checksum == GbaRomFormat::calculateChecksum(gbaheader);
}

}
