#include "disassemblerbase.h"
#include <cctype>

namespace REDasm {

DisassemblerBase::DisassemblerBase(Buffer buffer, FormatPlugin *format): DisassemblerFunctions(), _format(format), _buffer(buffer)
{
    this->_symboltable = format->symbols();
}

DisassemblerBase::~DisassemblerBase()
{
    delete this->_format;
}

Buffer &DisassemblerBase::buffer()
{
    return this->_buffer;
}

FormatPlugin *DisassemblerBase::format()
{
    return this->_format;
}

SymbolTable *DisassemblerBase::symbolTable()
{
    return this->_symboltable;
}

bool DisassemblerBase::hasReferences(const SymbolPtr& symbol)
{
    if(!symbol)
        return false;

    return this->_referencetable.hasReferences(symbol);
}

ReferenceVector DisassemblerBase::getReferences(const SymbolPtr& symbol)
{
    if(symbol->is(SymbolTypes::Pointer))
    {
        SymbolPtr ptrsymbol = this->dereferenceSymbol(symbol);

        if(ptrsymbol)
            return this->_referencetable.referencesToVector(ptrsymbol);
    }

    if(symbol)
        return this->_referencetable.referencesToVector(symbol);

    return ReferenceVector();
}

u64 DisassemblerBase::getReferencesCount(const SymbolPtr &symbol)
{
    return this->_referencetable.referencesCount(symbol);
}

u64 DisassemblerBase::locationIsString(address_t address, bool *wide) const
{
    u64 count = this->locationIsStringT<char>(address, ::isprint, [](u16 b) -> bool { return ::isalnum(b) || ::isspace(b); });

    if(count == 1) // Try with wide strings
    {
        count = this->locationIsStringT<u16>(address, [](u16 wb) -> bool { u8 b1 = wb & 0xFF, b2 = (wb & 0xFF00) >> 8; return ::isprint(b1) && !b2; },
                                                      [](u16 wb) -> bool { u8 b1 = wb & 0xFF, b2 = (wb & 0xFF00) >> 8; return (::isspace(b1) || ::isalnum(b1)) && !b2; } );

        if(wide)
            *wide = true;
    }

    return count;
}

std::string DisassemblerBase::readString(const SymbolPtr &symbol) const
{
    address_t memaddress = 0;

    if(symbol->is(SymbolTypes::Pointer) && this->dereferencePointer(symbol->address, memaddress))
        return this->readString(memaddress);

    return this->readString(symbol->address);
}

std::string DisassemblerBase::readWString(const SymbolPtr &symbol) const
{
    address_t memaddress = 0;

    if(symbol->is(SymbolTypes::Pointer) && this->dereferencePointer(symbol->address, memaddress))
        return this->readWString(memaddress);

    return this->readWString(symbol->address);
}

std::string DisassemblerBase::readHex(address_t address, u32 count) const
{
    Buffer data;

    if(!this->getBuffer(address, data))
        return std::string();

    count = std::min(static_cast<u64>(count), this->_buffer.length);

    std::stringstream ss;
    ss << std::hex << std::setfill('0');

    for(u64 i = 0; i < count; i++)
        ss << std::uppercase << std::setw(2) << static_cast<size_t>(data[i]);

    return ss.str();
}

SymbolPtr DisassemblerBase::dereferenceSymbol(const SymbolPtr& symbol, u64* value)
{
    address_t a = 0;
    SymbolPtr ptrsymbol;

    if(symbol->is(SymbolTypes::Pointer) && this->dereferencePointer(symbol->address, a))
        ptrsymbol = this->_symboltable->symbol(a);

    if(value)
        *value = a;

    return ptrsymbol;
}

bool DisassemblerBase::dereferencePointer(address_t address, u64 &value) const
{
    return this->readAddress(address, this->_format->bits() / 8, value);
}

bool DisassemblerBase::readAddress(address_t address, size_t size, u64 &value) const
{
    Segment* segment = this->_format->segment(address);

    if(!segment || segment->is(SegmentTypes::Bss))
        return false;

    offset_t offset = this->_format->offset(address);
    return this->readOffset(offset, size, value);
}

bool DisassemblerBase::getBuffer(address_t address, Buffer &data) const
{
    Segment* segment = this->_format->segment(address);

    if(!segment || segment->is(SegmentTypes::Bss))
        return false;

    data = this->_buffer + this->_format->offset(address);
    return true;
}

bool DisassemblerBase::readOffset(offset_t offset, size_t size, u64 &value) const
{
    Buffer pdest = this->_buffer + offset;

    if(size == 1)
        value = *reinterpret_cast<u8*>(pdest.data);
    else if(size == 2)
        value = *reinterpret_cast<u16*>(pdest.data);
    else if(size == 4)
        value = *reinterpret_cast<u32*>(pdest.data);
    else if(size == 8)
        value = *reinterpret_cast<u64*>(pdest.data);
    else
    {
        REDasm::log("Invalid size: " + std::to_string(size));
        return false;
    }

    return true;
}

std::string DisassemblerBase::readString(address_t address) const
{
    return this->readStringT<char>(address, [](char b, std::string& s) {
        bool r = ::isprint(b);
        if(r) s += b;
        return r;
    });
}

std::string DisassemblerBase::readWString(address_t address) const
{
    return this->readStringT<u16>(address, [](u16 wb, std::string& s) {
        u8 b1 = wb & 0xFF, b2 = (wb & 0xFF00) >> 8;
        bool r = ::isprint(b1) && !b2;
        if(r) s += static_cast<char>(b1);
        return r;
    });
}

} // namespace REDasm
