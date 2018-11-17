#ifndef DEX_H
#define DEX_H

// https://source.android.com/devices/tech/dalvik/dex-format

#include "../../plugins/plugins.h"
#include "../../assemblers/dalvik/dalvik_metadata.h"
#include "dex_header.h"

namespace REDasm {

class DEXFormat : public FormatPluginT<DEXHeader>
{
    public:
        DEXFormat(Buffer& buffer);
        virtual const char* name() const;
        virtual const char* assembler() const;
        virtual u32 bits() const;
        virtual endianness_t endianness() const;
        virtual bool load();

    public:
        bool getMethodOffset(u64 idx, offset_t &offset) const;
        bool getStringOffset(u64 idx, offset_t &offset) const;
        std::string getString(u64 idx) const;
        std::string getType(u64 idx) const;
        std::string getMethod(u64 idx) const;
        std::string getMethodProto(u64 idx) const;
        std::string getField(u64 idx) const;
        std::string getReturnType(u64 methodidx) const;
        std::string getParameters(u64 methodidx) const;
        bool getMethodInfo(u64 methodidx, DEXEncodedMethod& dexmethod);
        bool getDebugInfo(u64 methodidx, DEXDebugInfo& debuginfo);

    private:
        bool getClassData(const DEXClassIdItem& dexclass, DEXClassData& dexclassdata);
        void loadMethod(const DEXEncodedMethod& dexmethod, u16 &idx);
        void loadClass(const DEXClassIdItem& dexclass);

    private:
        std::string getNormalizedString(u64 idx) const;
        std::string getTypeList(u64 typelistoff) const;
        static bool validateSignature(DEXHeader *format);
        static std::string normalized(const std::string& type);

    private:
        std::unordered_map<u64, DEXCodeItem*> m_codeitems;
        std::unordered_map<u64, DEXEncodedMethod> m_encmethods;
        DEXTypeIdItem* m_types;
        DEXStringIdItem* m_strings;
        DEXMethodIdItem* m_methods;
        DEXFieldIdItem* m_fields;
        DEXProtoIdItem* m_protos;
};

DECLARE_FORMAT_PLUGIN(DEXFormat, dex)

} // namespace REDasm

#endif // DEX_H
