#ifndef FORMAT_H
#define FORMAT_H

#include <unordered_map>
#include "../disassembler/disassemblerapi.h"
#include "../disassembler/types/symboltable.h"
#include "../disassembler/listing/listingdocument.h"
#include "../support/endianness.h"
#include "../analyzer/analyzer.h"
#include "base.h"

#define DECLARE_FORMAT_PLUGIN(T, id) inline FormatPlugin* id##_formatPlugin(const Buffer& buffer) { return REDasm::declareFormatPlugin<T>(buffer); }

namespace REDasm {

template<typename T> T* declareFormatPlugin(const Buffer& buffer)
{
    std::unique_ptr<T> t = std::make_unique<T>(buffer);

    if(t->load())
        return t.release();

    return NULL;
}

namespace FormatFlags {
    enum: u32 { None                 = 0,
                Binary               = 1, // Internal Use
                IgnoreUnexploredCode = 2 };
}

class FormatPlugin: public Plugin
{
    public:
        FormatPlugin(const Buffer& buffer);
        bool isBinary() const;
        const Buffer& buffer() const;
        ListingDocument* document();
        const SignatureFiles& signatures() const;
        u64 addressWidth() const;

    public:
        virtual offset_t offset(address_t address) const;
        virtual Analyzer *createAnalyzer(DisassemblerAPI* disassembler, const SignatureFiles &signatures) const;
        virtual const char* assembler() const = 0;
        virtual u32 bits() const = 0;
        virtual u32 flags() const;
        virtual endianness_t endianness() const;
        virtual bool load() = 0;

    protected:
        ListingDocument m_document;
        SignatureFiles m_signatures;
        Buffer m_buffer;
};

template<typename T> class FormatPluginT: public FormatPlugin
{
    public:
        FormatPluginT(const Buffer& buffer): FormatPlugin(buffer) { m_format = reinterpret_cast<T*>(buffer.data); }
        template<typename U> inline offset_t fileoffset(U* ptr) const { return reinterpret_cast<u8*>(ptr) - reinterpret_cast<u8*>(this->m_format); }
        template<typename U> inline U* pointer(s64 offset) const { return reinterpret_cast<U*>(reinterpret_cast<u8*>(m_format) + offset); }
        template<typename U, typename V> inline U* relpointer(V* base, s64 offset) const { return reinterpret_cast<U*>(reinterpret_cast<u8*>(base) + offset); }

    protected:
        T* m_format;
};

class FormatPluginB: public FormatPluginT<u8>
{
    public:
        FormatPluginB(const Buffer& buffer): FormatPluginT<u8>(buffer) { }
};

typedef std::function<FormatPlugin*(const Buffer&)> FormatPlugin_Entry;

}

#endif // FORMAT_H
