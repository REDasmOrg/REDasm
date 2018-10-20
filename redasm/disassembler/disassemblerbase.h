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
        virtual ~DisassemblerBase();

    public: // Primitive functions
        virtual FormatPlugin* format();
        virtual ListingDocument* document();
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
        virtual bool getBuffer(address_t address, Buffer& data) const;
        virtual bool readAddress(address_t address, size_t size, u64 *value) const;
        virtual bool readOffset(offset_t offset, size_t size, u64 *value) const;
        virtual std::string readString(address_t address) const;
        virtual std::string readWString(address_t address) const;

   private:
        template<typename T> std::string readStringT(address_t address, std::function<bool(T, std::string&)> fill) const;
        template<typename T> u64 locationIsStringT(address_t address, std::function<bool(T)> isp, std::function<bool(T)> isa) const;

   protected:
        ReferenceTable m_referencetable;
        ListingDocument* m_document;
        FormatPlugin* m_format;
};

template<typename T> std::string DisassemblerBase::readStringT(address_t address, std::function<bool(T, std::string&)> fill) const
{
    Buffer b = m_format->buffer() + m_format->offset(address);
    std::string s;

    while(fill(*reinterpret_cast<T*>(b.data), s) && !b.eob())
        b += sizeof(T);

    return s;
}

template<typename T> u64 DisassemblerBase::locationIsStringT(address_t address, std::function<bool(T)> isp, std::function<bool(T)> isa) const
{
    if(!m_document->segment(address))
        return 0;

    u64 alphacount = 0, count = 0;
    Buffer b = m_format->buffer() + m_format->offset(address);

    while(!b.eob() && isp(*reinterpret_cast<T*>(b.data)))
    {
        count++;

        if(isa(*reinterpret_cast<T*>(b.data)))
            alphacount++;

        if(count >= MIN_STRING)
            break;

        b += sizeof(T);
    }

    if(!count || ((static_cast<double>(alphacount) / count) < 0.51)) // ...it might be just data, check alpha ratio...
        return 0;

    return count;
}

} // namespace REDasm

#endif // DISASSEMBLERBASE_H
