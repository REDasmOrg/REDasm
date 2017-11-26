#ifndef FORMAT_H
#define FORMAT_H

#include <unordered_map>
#include "../disassembler/disassemblerfunctions.h"
#include "../disassembler/types/symboltable.h"
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

class FormatPlugin: public Plugin
{
    public:
        FormatPlugin();
        const SegmentVector& segments() const;
        const SymbolTable& symbols() const;
        Segment *segment(address_t address);
        virtual offset_t offset(address_t address) const;
        virtual Analyzer *createAnalyzer(DisassemblerFunctions* dfunctions) const;

    public:
        virtual u32 bits() const = 0;
        virtual const char* processor() const = 0;
        virtual bool load(u8* format);

    protected:
        void defineSegment(const std::string& name, offset_t offset, address_t address, u64 size, u32 flags);
        void defineSymbol(address_t address, const std::string& name, u32 flags);
        void defineFunction(address_t address, const std::string &name);
        void defineEntryPoint(address_t address);

    private:
        SymbolTable _symbol;
        SegmentVector _segments;
};

template<typename T> class FormatPluginT: public FormatPlugin
{
    public:
        FormatPluginT(): FormatPlugin() { }
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
