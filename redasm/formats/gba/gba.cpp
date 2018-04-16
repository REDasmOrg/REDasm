#include "gba.h"
#include <cstring>

#define GBAROM_OFFSET 0
#define GBAROM_START_ADDR 0x8000000
#define GBAROM_SIZE 0x2000000

#define GBAEWRAM_OFFSET 0
#define GBAEWRAM_START_ADDR 0x2000000
#define GBAEW_SIZE 0x40000

#define GBAIWRAM_OFFSET 0
#define GBAIWRAM_START_ADDR 0x3000000
#define GBAIW_SIZE 0x80000

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

const char *GbaRomFormat::assembler() const
{
    return "arm"; //"arm7tdmi";
}

bool GbaRomFormat::load(u8* rawformat)
{
    GbaRomHeader* format = convert(rawformat);

    if(!(format->fixed_val == 0x96)) // no signature/magic number is present in GBA ROMS
        return false;

    this->defineSegment("EWRAM", GBAEWRAM_OFFSET, GBAEWRAM_START_ADDR, GBAEW_SIZE, SegmentTypes::Bss);
    this->defineSegment("IWRAM", GBAIWRAM_OFFSET, GBAIWRAM_START_ADDR, GBAIW_SIZE, SegmentTypes::Bss);
    this->defineSegment("ROM", GBAROM_OFFSET, GBAROM_START_ADDR, GBAROM_SIZE, SegmentTypes::Code | SegmentTypes::Data);

    this->defineEntryPoint(get_rom_ep(format->entry_point));
    FormatPluginT<GbaRomHeader>::load(rawformat);
    return true;
}

u32 GbaRomFormat::flags() const
{
    return FormatFlags::IgnoreUnexploredCode; // FIXME
}

u32 GbaRomFormat::get_rom_ep(u32 ep_branch)
{
  if ((ep_branch & 0x0A000000) != 0x0A000000) {
    return 0;
  }

  u32 ep_val = (ep_branch & 0xFFFFFF);
  if ((ep_val & 0x800000) != 0) {
    ep_val |= ~0xFFFFFF;
  }

  return GBAROM_START_ADDR + 8 + (ep_val * 4); // Due to the pipeline nature of the ARM7TDMI processor, the PC value would be N+8 in ARM-STATE (N = address of the istruction)
}

}
