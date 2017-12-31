#ifndef DEX_H
#define DEX_H

// https://source.android.com/devices/tech/dalvik/dex-format

#include "../../plugins/plugins.h"
#include "../../processors/dalvik/dalvik_metadata.h"
#include "dex_header.h"

namespace REDasm {

class DEXFormat : public FormatPluginT<DEXHeader>
{
    public:
        DEXFormat();
        virtual const char* name() const;
        virtual u32 bits() const;
        virtual const char* processor() const;
        virtual endianness_t endianness() const;
        virtual bool load(u8 *rawformat);

    public:
        std::string getString(u32 idx) const;
        std::string getMethod(u32 idx) const;

    private:
        bool getClassData(const DEXClassItem& dexclass, DEXClassData& dexclassdata);
        void loadMethod(const DEXClassItem &dexclass, const DEXEncodedMethod& dexmethod);
        void loadClass(const DEXClassItem& dexclass);

    private:
        u32 getULeb128(u8 **data) const;
        static bool validateSignature(DEXHeader *format);
        static std::string normalized(const std::string& classname, const std::string& methodname = std::string());

    private:
        DEXTypeItem* _types;
        DEXStringItem* _strings;
        DEXMethodItem* _methods;
};

DECLARE_FORMAT_PLUGIN(DEXFormat, dex)

} // namespace REDasm

#endif // DEX_H
