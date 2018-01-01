#include "dex.h"
#include "dex_constants.h"

namespace REDasm {

DEXFormat::DEXFormat(): _types(NULL), _strings(NULL), _methods(NULL), _fields(NULL), _protos(NULL)
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

    if((!format->method_ids_off || !format->method_ids_size) || (!format->proto_ids_off || !format->proto_ids_size))
        return false;

    this->_types = pointer<DEXTypeItem>(format->type_ids_off);
    this->_strings = pointer<DEXStringItem>(format->string_ids_off);
    this->_methods = pointer<DEXMethodItem>(format->method_ids_off);
    this->_protos = pointer<DEXProtoItem>(format->proto_ids_off);

    if(format->field_ids_off && format->field_ids_size)
        this->_fields = pointer<DEXFieldItem>(format->field_ids_off);

    this->defineSegment("DATA", format->data_off, format->data_off, format->data_size, SegmentTypes::Code);
    DEXClassItem* dexclasses = pointer<DEXClassItem>(format->class_defs_off);

    for(u32 i = 0, sz = 0; sz < format->class_defs_size; i++, sz += sizeof(DEXClassItem))
        this->loadClass(dexclasses[i]);

    FormatPluginT<DEXHeader>::load(rawformat);
    return true;
}

std::string DEXFormat::getString(u32 idx) const
{
    if(!this->_strings)
        return std::string();

    u8* pstringdata = pointer<u8>((this->_strings + idx)->string_data_off);
    u32 len = this->getULeb128(&pstringdata);

    return std::string(reinterpret_cast<const char*>(pstringdata), len);
}

std::string DEXFormat::getType(u32 idx) const
{
    if(idx >= this->_format->type_ids_size)
        return "type_" + std::to_string(idx);

    const DEXTypeItem& dextype = this->_types[idx];
    return this->getNormalizedString(dextype.descriptor_idx);
}

std::string DEXFormat::getMethod(u32 idx) const
{
    if(idx >= this->_format->method_ids_size)
        return "method_" + std::to_string(idx);

    const DEXMethodItem& dexmethod = this->_methods[idx];

    return this->getType(dexmethod.class_idx) + "->" +
            this->getNormalizedString(dexmethod.name_idx);
}

std::string DEXFormat::getMethodProto(u32 idx) const
{
    return this->getMethod(idx) + this->getParameters(idx) + ":" + this->getReturnType(idx);
}

std::string DEXFormat::getField(u32 idx) const
{
    if(!this->_fields || (idx >= this->_format->field_ids_size))
        return "field_" + std::to_string(idx);

    const DEXFieldItem& dexfield = this->_fields[idx];

    return this->getType(dexfield.class_idx) + "->" +
           this->getNormalizedString(dexfield.name_idx) + ":" + this->getType(dexfield.type_idx);
}

std::string DEXFormat::getReturnType(u32 methodidx) const
{
    if(methodidx >= this->_format->method_ids_size)
        return std::string();

    const DEXMethodItem& dexmethod = this->_methods[methodidx];
    const DEXProtoItem& dexproto = this->_protos[dexmethod.proto_idx];

    return this->getNormalizedString(this->_types[dexproto.return_type_idx].descriptor_idx);
}

std::string DEXFormat::getParameters(u32 methodidx) const
{
    if(methodidx >= this->_format->method_ids_size)
        return std::string();

    const DEXMethodItem& dexmethod = this->_methods[methodidx];
    const DEXProtoItem& dexproto = this->_protos[dexmethod.proto_idx];

    if(!dexproto.parameters_off)
        return "()";

    return "(" + this->getTypeList(dexproto.parameters_off) + ")";
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

void DEXFormat::loadMethod(const DEXEncodedMethod &dexmethod)
{
    if(!dexmethod.code_off)
        return;

    DEXCodeItem* dexcode = pointer<DEXCodeItem>(dexmethod.code_off);
    this->defineFunction(fileoffset(&dexcode->insns), this->getMethod(dexmethod.method_idx_diff), dexmethod.method_idx_diff);
}

void DEXFormat::loadClass(const DEXClassItem &dexclass)
{
    DEXClassData dexclassdata;

    if(!this->getClassData(dexclass, dexclassdata))
        return;

    std::for_each(dexclassdata.direct_methods.begin(), dexclassdata.direct_methods.end(), [this, dexclass](const DEXEncodedMethod& dexmethod) {
        this->loadMethod(dexmethod);
    });

    std::for_each(dexclassdata.virtual_methods.begin(), dexclassdata.virtual_methods.end(), [this, dexclass](const DEXEncodedMethod& dexmethod) {
        this->loadMethod(dexmethod);
    });
}

std::string DEXFormat::getNormalizedString(u32 idx) const
{
    return this->normalized(this->getString(idx));
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

std::string DEXFormat::getTypeList(u32 typelistoff) const
{
    u32 size = *pointer<u32>(typelistoff);
    DEXTypeItem* dextype = pointer<DEXTypeItem>(typelistoff + sizeof(u32));

    std::string s;

    for(u32 i = 0; i < size; i++)
    {
        if(i)
            s += ", ";

        s += this->getType(dextype[i].descriptor_idx);
    }

    return s;
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

std::string DEXFormat::normalized(const std::string &type)
{
    if(type[0] == '[')
        return DEXFormat::normalized(type.substr(1)) + "[]";

    if(type == "V")
        return "void";
    else if(type == "Z")
        return "boolean";
    else if(type == "B")
        return "byte";
    else if(type == "S")
        return "short";
    else if(type == "C")
        return "char";
    else if(type == "I")
        return "int";
    else if(type == "J")
        return "long";
    else if(type == "F")
        return "float";
    else if(type == "D")
        return "double";

    std::string s = type;

    if(s.front() == 'L')
       s.erase(s.begin());

    if(s.back() == ';')
        s.pop_back();

    std::replace(s.begin(), s.end(), '/', '.');
    return s;
}

} // namespace REDasm
