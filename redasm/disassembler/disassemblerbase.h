#ifndef DISASSEMBLERBASE_H
#define DISASSEMBLERBASE_H

#include <functional>
#include "../plugins/format.h"
#include "types/referencetable.h"
#include "disassemblerapi.h"

namespace REDasm {

class DisassemblerBase: public DisassemblerAPI
{
    public:
        DisassemblerBase(FormatPlugin* format);

    public: // Primitive functions
        virtual FormatPlugin* format();
        virtual ListingDocument* document();
        virtual ReferenceTable* references();
        virtual ReferenceVector getReferences(address_t address);
        virtual u64 getReferencesCount(address_t address);
        virtual void pushReference(address_t address, address_t refbyaddress);
        virtual void checkLocation(address_t fromaddress, address_t address);
        virtual bool checkString(address_t fromaddress, address_t address);
        virtual int checkAddressTable(const InstructionPtr &instruction, address_t startaddress);
        virtual u64 locationIsString(address_t address, bool *wide = NULL) const;
        virtual std::string readString(const SymbolPtr& symbol) const;
        virtual std::string readWString(const SymbolPtr& symbol) const;
        virtual std::string readHex(address_t address, u64 count) const;
        virtual SymbolPtr dereferenceSymbol(const SymbolPtr &symbol, u64 *value = NULL);
        virtual bool dereference(address_t address, u64 *value) const;
        virtual bool getBuffer(address_t address, BufferRef& data) const;
        virtual bool readAddress(address_t address, size_t size, u64 *value) const;
        virtual bool readOffset(offset_t offset, size_t size, u64 *value) const;
        virtual std::string readString(address_t address) const;
        virtual std::string readWString(address_t address) const;

   private:
        template<typename T> std::string readStringT(address_t address, std::function<bool(T, std::string&)> fill) const;
        template<typename T> u64 locationIsStringT(address_t address, std::function<bool(T)> isp, std::function<bool(T)> isa) const;

   protected:
        std::unique_ptr<FormatPlugin> m_format;
        ReferenceTable m_referencetable;
        ListingDocument* m_document;
};

template<typename T> std::string DisassemblerBase::readStringT(address_t address, std::function<bool(T, std::string&)> fill) const
{
    BufferRef b = m_format->buffer(address);
    std::string s;

    while(!b.eob() && fill(static_cast<T>(b), s))
        b.advance(sizeof(T));

    return s;
}

template<typename T> u64 DisassemblerBase::locationIsStringT(address_t address, std::function<bool(T)> isp, std::function<bool(T)> isa) const
{
    if(!m_document->segment(address))
        return 0;

    u64 alphacount = 0, count = 0;
    BufferRef buffer = m_format->buffer(address);

    while(!buffer.eob() && isp(static_cast<T>(buffer)))
    {
        count++;

        if(isa(static_cast<T>(buffer)))
            alphacount++;

        if(count >= MIN_STRING)
            break;

        buffer.advance(sizeof(T));
    }

    if(!count || ((static_cast<double>(alphacount) / count) < 0.51)) // ...it might be just data, check alpha ratio...
        return 0;

    return count;
}

} // namespace REDasm

#endif // DISASSEMBLERBASE_H
