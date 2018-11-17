#include "dex.h"
#include "dex_statemachine.h"
#include "dex_constants.h"
#include "dex_utils.h"
#include <cctype>

namespace REDasm {

DEXFormat::DEXFormat(Buffer &buffer): FormatPluginT<DEXHeader>(buffer), m_types(NULL), m_strings(NULL), m_methods(NULL), m_fields(NULL), m_protos(NULL) { }
const char *DEXFormat::name() const { return "DEX"; }
u32 DEXFormat::bits() const { return 32; }
const char *DEXFormat::assembler() const { return "dalvik"; }

endianness_t DEXFormat::endianness() const
{
    if(this->m_format->endian_tag == DEX_ENDIAN_CONSTANT)
        return Endianness::LittleEndian;

    return Endianness::BigEndian;
}

bool DEXFormat::load()
{
    if(!DEXFormat::validateSignature(m_format) || (!m_format->data_off || !m_format->data_size))
        return false;

    if((!m_format->type_ids_off || !m_format->type_ids_size) || (!m_format->string_ids_off || !m_format->string_ids_size))
        return false;

    if((!m_format->method_ids_off || !m_format->method_ids_size) || (!m_format->proto_ids_off || !m_format->proto_ids_size))
        return false;

    REDasm::log("Loading DEX Version " + std::string(m_format->version, 3));

    m_types = pointer<DEXTypeIdItem>(m_format->type_ids_off);
    m_strings = pointer<DEXStringIdItem>(m_format->string_ids_off);
    m_methods = pointer<DEXMethodIdItem>(m_format->method_ids_off);
    m_protos = pointer<DEXProtoIdItem>(m_format->proto_ids_off);

    if(m_format->field_ids_off && m_format->field_ids_size)
        m_fields = pointer<DEXFieldIdItem>(m_format->field_ids_off);

    m_document.segment("DATA", m_format->data_off, m_format->data_off, m_format->data_size, SegmentTypes::Code);
    DEXClassIdItem* dexclasses = pointer<DEXClassIdItem>(m_format->class_defs_off);

    for(u32 i = 0; i < m_format->class_defs_size; i++)
        this->loadClass(dexclasses[i]);

    return true;
}

bool DEXFormat::getMethodOffset(u64 idx, offset_t &offset) const
{
    auto it = m_codeitems.find(idx);

    if(it == m_codeitems.end())
        return false;

    DEXCodeItem* dexcode = it->second;
    offset = fileoffset(&dexcode->insns);
    return true;
}

bool DEXFormat::getStringOffset(u64 idx, offset_t& offset) const
{
    if(!m_strings || (idx >= m_format->string_ids_size))
        return false;

    u8* pstringdata = pointer<u8>(m_strings[idx].string_data_off);
    DEXUtils::getULeb128(&pstringdata);
    offset = fileoffset(pstringdata);
    return true;
}

std::string DEXFormat::getString(u64 idx) const
{
    if(!m_strings)
        return std::string();

    u8* pstringdata = pointer<u8>(m_strings[idx].string_data_off);
    u32 len = DEXUtils::getULeb128(&pstringdata);

    return std::string(reinterpret_cast<const char*>(pstringdata), len);
}

std::string DEXFormat::getType(u64 idx) const
{
    if(idx >= m_format->type_ids_size)
        return "type_" + std::to_string(idx);

    const DEXTypeIdItem& dextype = m_types[idx];
    return this->getNormalizedString(dextype.descriptor_idx);
}

std::string DEXFormat::getMethod(u64 idx) const
{
    if(idx >= m_format->method_ids_size)
        return "method_" + std::to_string(idx);

    const DEXMethodIdItem& dexmethod = m_methods[idx];

    return this->getType(dexmethod.class_idx) + "->" +
           this->getNormalizedString(dexmethod.name_idx);
}

std::string DEXFormat::getMethodProto(u64 idx) const
{
    return this->getMethod(idx) + this->getParameters(idx) + ":" + this->getReturnType(idx);
}

std::string DEXFormat::getField(u64 idx) const
{
    if(!m_fields || (idx >= m_format->field_ids_size))
        return "field_" + std::to_string(idx);

    const DEXFieldIdItem& dexfield = m_fields[idx];

    return this->getType(dexfield.class_idx) + "->" +
           this->getNormalizedString(dexfield.name_idx) + ":" + this->getType(dexfield.type_idx);
}

std::string DEXFormat::getReturnType(u64 methodidx) const
{
    if(methodidx >= m_format->method_ids_size)
        return std::string();

    const DEXMethodIdItem& dexmethod = m_methods[methodidx];
    const DEXProtoIdItem& dexproto = m_protos[dexmethod.proto_idx];

    return this->getNormalizedString(m_types[dexproto.return_type_idx].descriptor_idx);
}

std::string DEXFormat::getParameters(u64 methodidx) const
{
    if(methodidx >= m_format->method_ids_size)
        return std::string();

    const DEXMethodIdItem& dexmethod = m_methods[methodidx];
    const DEXProtoIdItem& dexproto = m_protos[dexmethod.proto_idx];

    if(!dexproto.parameters_off)
        return "()";

    return "(" + this->getTypeList(dexproto.parameters_off) + ")";
}

bool DEXFormat::getMethodInfo(u64 methodidx, DEXEncodedMethod &dexmethod)
{
    auto it = m_encmethods.find(methodidx);

    if(it == m_encmethods.end())
        return false;

    dexmethod = it->second;
    return true;
}

bool DEXFormat::getDebugInfo(u64 methodidx, DEXDebugInfo &debuginfo)
{
    auto it = m_codeitems.find(methodidx);

    if(it == m_codeitems.end())
        return false;

    DEXCodeItem* dexcode = it->second;

    if(!dexcode->debug_info_off)
        return false;

    u8* pdebuginfo = pointer<u8>(dexcode->debug_info_off);
    debuginfo.line_start = DEXUtils::getULeb128(&pdebuginfo);
    debuginfo.parameters_size = DEXUtils::getULeb128(&pdebuginfo);

    for(u32 i = 0; i < debuginfo.parameters_size; i++)
    {
        s32 idx = DEXUtils::getULeb128p1(&pdebuginfo);

        if(idx == DEX_NO_INDEX)
            debuginfo.parameter_names.push_back(std::string());
        else
            debuginfo.parameter_names.push_back(this->getNormalizedString(idx));
    }

    DEXStateMachine dexstatemachine(fileoffset(&dexcode->insns), debuginfo);
    dexstatemachine.execute(pdebuginfo);
    return true;
}

bool DEXFormat::getClassData(const DEXClassIdItem &dexclass, DEXClassData &dexclassdata)
{
    if(!dexclass.class_data_off)
        return false;

    DEXEncodedField dexfield;
    DEXEncodedMethod dexmethod;
    u8* pclassdata = pointer<u8>(dexclass.class_data_off);

    dexclassdata.static_fields_size = DEXUtils::getULeb128(&pclassdata);
    dexclassdata.instance_fields_size = DEXUtils::getULeb128(&pclassdata);
    dexclassdata.direct_methods_size = DEXUtils::getULeb128(&pclassdata);
    dexclassdata.virtual_methods_size = DEXUtils::getULeb128(&pclassdata);

    for(u32 i = 0; i < dexclassdata.static_fields_size; i++)
    {
        dexfield.field_idx_diff = DEXUtils::getULeb128(&pclassdata);
        dexfield.access_flags = DEXUtils::getULeb128(&pclassdata);
        dexclassdata.static_fields.push_back(dexfield);
    }

    for(u32 i = 0; i < dexclassdata.instance_fields_size; i++)
    {
        dexfield.field_idx_diff = DEXUtils::getULeb128(&pclassdata);
        dexfield.access_flags = DEXUtils::getULeb128(&pclassdata);
        dexclassdata.instance_fields.push_back(dexfield);
    }

    for(u32 i = 0; i < dexclassdata.direct_methods_size; i++)
    {
        dexmethod.method_idx_diff = DEXUtils::getULeb128(&pclassdata);
        dexmethod.access_flags = DEXUtils::getULeb128(&pclassdata);
        dexmethod.code_off = DEXUtils::getULeb128(&pclassdata);
        dexclassdata.direct_methods.push_back(dexmethod);
    }

    for(u32 i = 0; i < dexclassdata.virtual_methods_size; i++)
    {
        dexmethod.method_idx_diff = DEXUtils::getULeb128(&pclassdata);
        dexmethod.access_flags = DEXUtils::getULeb128(&pclassdata);
        dexmethod.code_off = DEXUtils::getULeb128(&pclassdata);
        dexclassdata.virtual_methods.push_back(dexmethod);
    }

    return true;
}

void DEXFormat::loadMethod(const DEXEncodedMethod &dexmethod, u16& idx)
{
    if(!dexmethod.code_off)
        return;

    if(!idx)
        idx = dexmethod.method_idx_diff;
    else
        idx += dexmethod.method_idx_diff;

    DEXCodeItem* dexcode = pointer<DEXCodeItem>(dexmethod.code_off);

    m_encmethods[idx] = dexmethod;
    m_codeitems[idx] = dexcode;

    m_document.function(fileoffset(&dexcode->insns), this->getMethod(idx), idx);
}

void DEXFormat::loadClass(const DEXClassIdItem &dexclass)
{
    DEXClassData dexclassdata;

    if(!this->getClassData(dexclass, dexclassdata))
        return;

    u16 idx = 0;

    std::for_each(dexclassdata.direct_methods.begin(), dexclassdata.direct_methods.end(), [this, dexclass, &idx](const DEXEncodedMethod& dexmethod) {
        this->loadMethod(dexmethod, idx);
    });

    idx = 0;

    std::for_each(dexclassdata.virtual_methods.begin(), dexclassdata.virtual_methods.end(), [this, dexclass, &idx](const DEXEncodedMethod& dexmethod) {
        this->loadMethod(dexmethod, idx);
    });
}

std::string DEXFormat::getNormalizedString(u64 idx) const { return this->normalized(this->getString(idx)); }

std::string DEXFormat::getTypeList(u64 typelistoff) const
{
    u32 size = *pointer<u32>(typelistoff);
    DEXTypeItem* dextypeitem = pointer<DEXTypeItem>(typelistoff + sizeof(u32));

    std::string s;

    for(u32 i = 0; i < size; i++)
    {
        if(i)
            s += ", ";

        s += this->getType(dextypeitem[i].type_idx);
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
