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
        DEXFormat();
        virtual const char* name() const;
        virtual const char* assembler() const;
        virtual u32 bits() const;
        virtual u32 flags() const;
        virtual endianness_t endianness() const;
        virtual bool load(u8 *rawformat);

    public:
        bool getMethodOffset(u32 idx, offset_t &offset) const;
        bool getStringOffset(u32 idx, offset_t &offset) const;
        std::string getString(u32 idx) const;
        std::string getType(u32 idx) const;
        std::string getMethod(u32 idx) const;
        std::string getMethodProto(u32 idx) const;
        std::string getField(u32 idx) const;
        std::string getReturnType(u32 methodidx) const;
        std::string getParameters(u32 methodidx) const;
        bool getMethodInfo(u32 methodidx, DEXEncodedMethod& dexmethod);
        bool getDebugInfo(u32 methodidx, DEXDebugInfo& debuginfo);

    private:
        bool getClassData(const DEXClassIdItem& dexclass, DEXClassData& dexclassdata);
        void loadMethod(const DEXEncodedMethod& dexmethod, u16 &idx);
        void loadClass(const DEXClassIdItem& dexclass);

    private:
        std::string getNormalizedString(u32 idx) const;
        std::string getTypeList(u32 typelistoff) const;
        static bool validateSignature(DEXHeader *format);
        static std::string normalized(const std::string& type);

    private:
        std::unordered_map<u16, DEXCodeItem*> _codeitems;
        std::unordered_map<u16, DEXEncodedMethod> _encmethods;
        DEXTypeIdItem* _types;
        DEXStringIdItem* _strings;
        DEXMethodIdItem* _methods;
        DEXFieldIdItem* _fields;
        DEXProtoIdItem* _protos;
};

DECLARE_FORMAT_PLUGIN(DEXFormat, dex)

} // namespace REDasm

#endif // DEX_H
