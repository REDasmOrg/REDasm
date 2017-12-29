#include "dex.h"
#include "dex_constants.h"

namespace REDasm {

DEXFormat::DEXFormat(): _types(NULL), _strings(NULL), _methods(NULL)
{

}

const char *DEXFormat::name() const
{
    return "DEX";
}

u32 DEXFormat::bits() const
{
    return 32;
}

const char *DEXFormat::processor() const
{
    return "dalvik";
}

endianness_t DEXFormat::endianness() const
{
    if(this->_format->endian_tag == DEX_ENDIAN_CONSTANT)
        return Endianness::LittleEndian;

    return Endianness::BigEndian;
}

bool DEXFormat::load(u8 *rawformat)
{
    DEXHeader* format = convert(rawformat);

    if(!DEXFormat::validateSignature(format) || (!format->data_off || !format->data_size))
        return false;

    if((!format->type_ids_off || !format->type_ids_size) || (!format->string_ids_off || !format->string_ids_size))
        return false;

    if((!format->method_ids_off || !format->method_ids_size))
        return false;

    this->_types = pointer<DEXTypeItem>(format->type_ids_off);
    this->_strings = pointer<DEXStringItem>(format->string_ids_off);
    this->_methods = pointer<DEXMethodItem>(format->method_ids_off);

    this->defineSegment("DATA", format->data_off, format->data_off, format->data_size, SegmentTypes::Code);
    DEXClassItem* dexclasses = pointer<DEXClassItem>(format->class_defs_off);

    for(u32 i = 0, sz = 0; sz < format->class_defs_size; i++, sz += sizeof(DEXClassItem))
        this->loadClass(dexclasses[i]);

    FormatPluginT<DEXHeader>::load(rawformat);
    return true;
}

bool DEXFormat::getClassData(const DEXClassItem &dexclass, DEXClassData &dexclassdata)
{
    if(!dexclass.class_data_off)
        return false;

    DEXEncodedField dexfield;
    DEXEncodedMethod dexmethod;
    u8* pclassdata = pointer<u8>(dexclass.class_data_off);

    dexclassdata.static_fields_size = this->getULeb128(&pclassdata);
    dexclassdata.instance_fields_size = this->getULeb128(&pclassdata);
    dexclassdata.direct_methods_size = this->getULeb128(&pclassdata);
    dexclassdata.virtual_methods_size = this->getULeb128(&pclassdata);

    for(u32 i = 0; i < dexclassdata.static_fields_size; i++)
    {
        dexfield.field_idx_diff = this->getULeb128(&pclassdata);
        dexfield.access_flags = this->getULeb128(&pclassdata);
        dexclassdata.static_fields.push_back(dexfield);
    }

    for(u32 i = 0; i < dexclassdata.instance_fields_size; i++)
    {
        dexfield.field_idx_diff = this->getULeb128(&pclassdata);
        dexfield.access_flags = this->getULeb128(&pclassdata);
        dexclassdata.instance_fields.push_back(dexfield);
    }

    for(u32 i = 0; i < dexclassdata.direct_methods_size; i++)
    {
        dexmethod.method_idx_diff = this->getULeb128(&pclassdata);
        dexmethod.access_flags = this->getULeb128(&pclassdata);
        dexmethod.code_off = this->getULeb128(&pclassdata);
        dexclassdata.direct_methods.push_back(dexmethod);
    }

    for(u32 i = 0; i < dexclassdata.virtual_methods_size; i++)
    {
        dexmethod.method_idx_diff = this->getULeb128(&pclassdata);
        dexmethod.access_flags = this->getULeb128(&pclassdata);
        dexmethod.code_off = this->getULeb128(&pclassdata);
        dexclassdata.virtual_methods.push_back(dexmethod);
    }

    return true;
}

void DEXFormat::loadMethod(const DEXClassItem& dexclass, const DEXEncodedMethod &dexmethod)
{
    if(!dexmethod.code_off)
        return;

    std::string classname = this->getString(this->_types[dexclass.class_idx].descriptor_idx);
    std::string name = this->getString(this->_methods[dexmethod.method_idx_diff].name_idx);
    DEXCodeItem* dexcode = pointer<DEXCodeItem>(dexmethod.code_off);
    this->defineFunction(fileoffset(&dexcode->insns), classname + " " + name);
}

void DEXFormat::loadClass(const DEXClassItem &dexclass)
{
    DEXClassData dexclassdata;

    if(!this->getClassData(dexclass, dexclassdata))
        return;

    std::for_each(dexclassdata.direct_methods.begin(), dexclassdata.direct_methods.end(), [this, dexclass](const DEXEncodedMethod& dexmethod) {
        this->loadMethod(dexclass, dexmethod);
    });

    std::for_each(dexclassdata.virtual_methods.begin(), dexclassdata.virtual_methods.end(), [this, dexclass](const DEXEncodedMethod& dexmethod) {
        this->loadMethod(dexclass, dexmethod);
    });
}

u32 DEXFormat::getULeb128(u8 **data) const
{
    size_t i = 0;
    u32 value = 0;

    while(**data & 0x80)
    {
        value |= ((**data & 0x7F) << (i * 7));
        (*data)++;
        i++;
    }

    value |= ((**data & 0x7F) << (i * 7));
    (*data)++;
    return value;
}

std::string DEXFormat::getString(u32 idx) const
{
    if(!this->_strings)
        return std::string();

    u8* pstringdata = pointer<u8>((this->_strings + idx)->string_data_off);
    u32 len = this->getULeb128(&pstringdata);

    return std::string(reinterpret_cast<const char*>(pstringdata), len);
}

bool DEXFormat::validateSignature(DEXHeader* format)
{
    if(strncmp(format->dex, DEX_FILE_MAGIC, 3))
        return false;

    if(format->newline != '\n')
        return false;

    for(u32 i = 0; i < 3; i++)
    {
        if(!std::isdigit(format->version[i]))
            return false;
    }

    if(format->zero != '\0')
        return false;

    return true;
}

} // namespace REDasm
