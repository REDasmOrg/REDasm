#ifndef FORMAT_H
#define FORMAT_H

#include <unordered_map>
#include "../disassembler/disassemblerapi.h"
#include "../disassembler/types/symboltable.h"
#include "../support/endianness.h"
#include "../analyzer/analyzer.h"
#include "base.h"

#define DECLARE_FORMAT_PLUGIN(T, id) inline FormatPlugin* id##_formatPlugin(u8* data) { return REDasm::declareFormatPlugin<T>(data); }

namespace REDasm {

template<typename T> T* declareFormatPlugin(u8* data)
{
    T* t = new T();

    if(t->load(data))
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
        const SegmentList& segments() const;
        SymbolTable* symbols();
        Segment *segment(address_t address);
        Segment *segmentAt(u64 index);
        Segment *segmentByName(const std::string& name);
        Segment* entryPointSegment();
        const SignatureFiles& signatures() const;
        u64 addressWidth() const;

    public:
        virtual offset_t offset(address_t address) const;
        virtual Analyzer *createAnalyzer(DisassemblerAPI* disassembler, const SignatureFiles &signatures) const;
        virtual const char* assembler() const = 0;
        virtual u32 bits() const = 0;
        virtual u32 flags() const;
        virtual endianness_t endianness() const;
        virtual bool load(u8* format);

    protected:
        void addSignature(const std::string& signaturefile);
        void defineSegment(const std::string& name, offset_t offset, address_t address, u64 size, u32 flags);
        void defineSymbol(address_t address, const std::string& name, u32 type, u32 extratype = 0);
        void defineFunction(address_t address, const std::string &name, u32 extratype = 0);
        void defineEntryPoint(address_t address, u32 extratype = 0);

    private:
        SymbolTable _symbol;
        SegmentList _segments;
        SignatureFiles _signatures;
};

template<typename T> class FormatPluginT: public FormatPlugin
{
    public:
        FormatPluginT(): FormatPlugin() { }
        template<typename U> inline offset_t fileoffset(U* ptr) const { return reinterpret_cast<u8*>(ptr) - reinterpret_cast<u8*>(this->_format); }
        template<typename U> inline U* pointer(s64 offset) const { return reinterpret_cast<U*>(reinterpret_cast<u8*>(_format) + offset); }
        template<typename U, typename V> inline U* relpointer(V* base, s64 offset) const { return reinterpret_cast<U*>(reinterpret_cast<u8*>(base) + offset); }

    protected:
        inline T* convert(u8* format) { _format = reinterpret_cast<T*>(format); return _format; }

    protected:
        T* _format;
};

class FormatPluginB: public FormatPluginT<u8>
{
    public:
        FormatPluginB(): FormatPluginT<u8>() { }
        virtual bool load(u8* format) { this->_format = format; return FormatPluginT<u8>::load(format); }
};

typedef std::function<FormatPlugin*(u8*)> FormatPlugin_Entry;

}

#endif // FORMAT_H
