#ifndef BINARY_H
#define BINARY_H

#include "../../plugins/plugins.h"

namespace REDasm {

class BinaryFormat : public FormatPluginB
{
    public:
        BinaryFormat();
        virtual const char* name() const;
        virtual const char* processor() const;
        virtual u32 bits() const;
        virtual bool load(u8 *rawformat);
        virtual bool isBinary() const;
        void build(const std::string& proc, u32 bits, offset_t offset, address_t baseaddress, address_t entry, u64 size);

    private:
        std::string _processor;
        u32 _bits;

};

DECLARE_FORMAT_PLUGIN(BinaryFormat, binary)

} // namespace REDasm

#endif // BINARY_H
