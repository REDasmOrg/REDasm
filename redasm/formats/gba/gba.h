#ifndef GBA_H
#define GBA_H

#include "../../plugins/plugins.h"

#define GBAROM_HEADER_SIZE 192
#define NINTENDO_LOGO_SIZE 156
#define GAME_TITLE_SIZE 12
#define GAME_CODE_SIZE 4
#define MAKER_CODE_SIZE 2

namespace REDasm {

struct GbaRomHeader // From: http://problemkaputt.de/gbatek.htm#gbacartridgeheader
{
    u32 entry_point;
    u8 nintendo_logo[NINTENDO_LOGO_SIZE];
    u8 game_title[GAME_TITLE_SIZE];
    u8 game_code[GAME_CODE_SIZE];
    u8 maker_code[MAKER_CODE_SIZE];
    u8 fixed_val;
    u8 main_unit_code;
    u8 device_type;
    u8 reserved_area[7];
    u8 software_version;
    u8 header_checksum;
    u8 reserved_area_2[2];
    u32 ram_entry_point;
    u8 boot_mode;
    u8 slave_id;
    u8 unused[26];
    u32 joybus_entry_point;
};

class GbaRomFormat: public FormatPluginT<GbaRomHeader>
{
    public:
        GbaRomFormat();
        virtual const char* name() const;
        virtual u32 bits() const;
        virtual const char* assembler() const;
        virtual bool load(u8 *rawformat);
        virtual u32 flags() const;
    private:
        virtual u32 get_rom_ep(u32 ep_branch);
};

DECLARE_FORMAT_PLUGIN(GbaRomFormat, gbarom)

}

#endif // GBA_H
