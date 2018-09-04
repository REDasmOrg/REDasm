#ifndef FORMAT_H
#define FORMAT_H

#include <unordered_map>
#include "../disassembler/disassemblerapi.h"
#include "../disassembler/types/symboltable.h"
#include "../disassembler/listing/listingdocument.h"
#include "../support/endianness.h"
#include "../analyzer/analyzer.h"
#include "disassembler/algorithm.h"
#include "base.h"

#define DECLARE_FORMAT_PLUGIN(T, id) inline FormatPlugin* id##_formatPlugin(u8* data, u64 length) { return REDasm::declareFormatPlugin<T>(data, length); }

namespace REDasm {

template<typename T> T* declareFormatPlugin(u8* data, u64 length)
{
    T* t = new T();

    if(t->load(data, length))
        return t;

    delete t;
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
        FormatPlugin();
        bool isBinary() const;
        ListingDocument* document();
        Segment* entryPointSegment();
        const SignatureFiles& signatures() const;
        u64 addressWidth() const;

    public:
        virtual offset_t offset(address_t address) const;
        virtual Analyzer *createAnalyzer(DisassemblerAPI* disassembler, const SignatureFiles &signatures) const;
        virtual DisassemblerAlgorithm* createAlgorithm(DisassemblerAPI* disassembler, AssemblerPlugin* assemblerplugin) const;
        virtual const char* assembler() const = 0;
        virtual u32 bits() const = 0;
        virtual u32 flags() const;
        virtual endianness_t endianness() const;
        virtual bool load(u8* format);

    protected:
        ListingDocument m_document;
        SignatureFiles m_signatures;
};

template<typename T> class FormatPluginT: public FormatPlugin
{
    public:
        FormatPluginT(): FormatPlugin() { }
        template<typename U> inline offset_t fileoffset(U* ptr) const { return reinterpret_cast<u8*>(ptr) - reinterpret_cast<u8*>(this->m_format); }
        template<typename U> inline U* pointer(s64 offset) const { return reinterpret_cast<U*>(reinterpret_cast<u8*>(m_format) + offset); }
        template<typename U, typename V> inline U* relpointer(V* base, s64 offset) const { return reinterpret_cast<U*>(reinterpret_cast<u8*>(base) + offset); }

    protected:
        inline T* convert(u8* format) { m_format = reinterpret_cast<T*>(format); return m_format; }

    protected:
        T* m_format;
};

class FormatPluginB: public FormatPluginT<u8>
{
    public:
        FormatPluginB(): FormatPluginT<u8>() { }
        virtual bool load(u8* format) { this->m_format = format; return FormatPluginT<u8>::load(format); }
};

typedef std::function<FormatPlugin*(u8*, u64)> FormatPlugin_Entry;

}

#endif // FORMAT_H
