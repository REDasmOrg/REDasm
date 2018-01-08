#ifndef DEX_HEADER_H
#define DEX_HEADER_H

#include "../../redasm.h"
#include "dex_constants.h"

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

struct DEXStringIdItem { u32 string_data_off; };
struct DEXTypeIdItem { u32 descriptor_idx; };
struct DEXProtoIdItem { u32 shorty_idx, return_type_idx, parameters_off; };

struct DEXFieldIdItem
{
    u16 class_idx, type_idx;
    u32 name_idx;
};

struct DEXMethodIdItem
{
    u16 class_idx, proto_idx;
    u32 name_idx;
};

struct DEXClassIdItem
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

struct DEXTypeItem { u16 type_idx; };

// Elaborated Structures

struct DEXEncodedField { u32 field_idx_diff, access_flags; };
struct DEXEncodedMethod { u32 method_idx_diff, access_flags, code_off; };

enum DEXDebugDataTypes {
    PrologueEnd, EpilogueBegin,
    Line, File, StartLocal, StartLocalExtended, EndLocal, RestartLocal
};

struct DEXDebugData
{
    u32 data_type, register_num;
    union { s32 line_no, file_idx, name_idx; };
    s32 type_idx, sig_idx;

    static DEXDebugData prologueEnd() { return { DEXDebugDataTypes::PrologueEnd, DEX_NO_INDEX_U, DEX_NO_INDEX, DEX_NO_INDEX, DEX_NO_INDEX }; }
    static DEXDebugData epilogueBegin() { return { DEXDebugDataTypes::EpilogueBegin, DEX_NO_INDEX_U, DEX_NO_INDEX, DEX_NO_INDEX, DEX_NO_INDEX }; }
    static DEXDebugData endLocal(u32 registernum) { return { DEXDebugDataTypes::EndLocal, registernum, DEX_NO_INDEX, DEX_NO_INDEX, DEX_NO_INDEX }; }
    static DEXDebugData restartLocal(u32 registernum) { return { DEXDebugDataTypes::RestartLocal, registernum, DEX_NO_INDEX, DEX_NO_INDEX, DEX_NO_INDEX }; }
    static DEXDebugData line(s32 line) { return { DEXDebugDataTypes::Line, DEX_NO_INDEX_U, line, DEX_NO_INDEX, DEX_NO_INDEX }; }
    static DEXDebugData file(s32 file) { return { DEXDebugDataTypes::File, DEX_NO_INDEX_U, file, DEX_NO_INDEX, DEX_NO_INDEX }; }
    static DEXDebugData local(u32 registernum, s32 nameidx, s32 typeidx) { return { DEXDebugDataTypes::StartLocal, registernum, nameidx, typeidx, DEX_NO_INDEX }; }
    static DEXDebugData localext(u32 registernum, s32 nameidx, s32 typeidx, s32 sigidx) { return { DEXDebugDataTypes::StartLocalExtended, registernum, nameidx, typeidx, sigidx }; }
};

struct DEXDebugInfo
{
    DEXDebugInfo(): line_start(DEX_NO_INDEX_U), parameters_size(0) { }

    u32 line_start, parameters_size;
    std::vector<std::string> parameter_names;
    std::unordered_map<u16, std::list<DEXDebugData> > debug_data;
};

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
