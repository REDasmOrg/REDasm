#ifndef DEX_HEADER_H
#define DEX_HEADER_H

#include "../../redasm.h"

namespace REDasm {

struct DEXHeader
{
    union {
        char magic[8];
        struct { char dex[3], newline, version[3], zero; };
    };

    u32 checksum;
    u8 signature[20];
    u32 file_size, header_size, endian_tag;
    u32 link_size, link_off, map_off;
    u32 string_ids_size, string_ids_off;
    u32 type_ids_size, type_ids_off;
    u32 proto_ids_size, proto_ids_off;
    u32 field_ids_size, field_ids_off;
    u32 method_ids_size, method_ids_off;
    u32 class_defs_size, class_defs_off;
    u32 data_size, data_off;
};

struct DEXStringItem { u32 string_data_off; };
struct DEXTypeItem { u32 descriptor_idx; };
struct DEXProtoItem { u32 shorty_idx, return_type_idx, parameters_off; };

struct DEXFieldItem
{
    u16 class_idx, type_idx;
    u32 name_idx;
};

struct DEXMethodItem
{
    u16 class_idx, proto_idx;
    u32 name_idx;
};

struct DEXClassItem
{
    u32 class_idx, access_flags, superclass_idx, interfaces_off;
    u32 source_file_idx, annotations_off, class_data_off, static_values_off;
};

struct DEXCodeItem
{
    u16 registers_size, ins_size, outs_size, tries_size;
    u32 debug_info_off, insn_size;
    u16 insns[1];
    //u16 padding;
    //DEXTryItem tries[1];
    //DEXEncodedCatchHandlerList handlers[1];
};

// Elaborated Structures

struct DEXEncodedField { u32 field_idx_diff, access_flags; };
struct DEXEncodedMethod { u32 method_idx_diff, access_flags, code_off; };

struct DEXClassData
{
    u32 static_fields_size, instance_fields_size;
    u32 direct_methods_size, virtual_methods_size;

    std::vector<DEXEncodedField> static_fields;
    std::vector<DEXEncodedField> instance_fields;
    std::vector<DEXEncodedMethod> direct_methods;
    std::vector<DEXEncodedMethod> virtual_methods;
};

} // namespace REDasm

#endif // DEX_HEADER_H
