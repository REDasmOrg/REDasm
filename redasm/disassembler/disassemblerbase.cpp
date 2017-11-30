#include "disassemblerbase.h"
#include <cctype>

namespace REDasm {

DisassemblerBase::DisassemblerBase(Buffer buffer, FormatPlugin *format): DisassemblerFunctions(), _format(format), _buffer(buffer)
{
    this->_symboltable = format->symbols(); // Initialize symbol table
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

SymbolTable *DisassemblerBase::symbols()
{
    return &this->_symboltable;
}

void DisassemblerBase::loggerCallback(const DisassemblerBase::ReportCallback &cb)
{
    this->_logcallback = cb;
}

void DisassemblerBase::statusCallback(const DisassemblerBase::ReportCallback &cb)
{
    this->_statuscallback = cb;
}

bool DisassemblerBase::dataToString(address_t address)
{
    Symbol* symbol = this->_symboltable.symbol(address);

    if(!symbol)
        return false;

    bool wide = false;
    this->locationIsString(address, &wide);

    std::string s;
    ReferenceVector refs = this->_referencetable.referencesToVector(symbol);

    symbol->type &= (~SymbolTypes::Data);
    symbol->type |= wide ? SymbolTypes::WideString : SymbolTypes::String;;

    if(wide)
    {
        symbol->type |= SymbolTypes::WideString;
        s = this->readWString(address);
    }
    else
    {
        symbol->type |= SymbolTypes::String;
        s = this->readString(address);
    }

    std::for_each(refs.begin(), refs.end(), [s, wide](InstructionPtr& instruction) {
        wide ? instruction->cmt("UNICODE: " + s) : instruction->cmt("STRING: " + s);
    });

    return this->_symboltable.rename(symbol, "str_" + REDasm::hex(address, 0, false));
}

bool DisassemblerBase::hasReferences(Symbol *symbol)
{
    if(!symbol)
        return false;

    return this->_referencetable.hasReferences(symbol);
}

ReferenceVector DisassemblerBase::getReferences(const Symbol *symbol)
{
    if(symbol->is(SymbolTypes::Pointer))
    {
        Symbol* ptrsymbol = this->dereferenceSymbol(symbol);

        if(ptrsymbol)
            return this->_referencetable.referencesToVector(ptrsymbol);
    }

    if(symbol)
        return this->_referencetable.referencesToVector(symbol);

    return ReferenceVector();
}

u64 DisassemblerBase::getReferencesCount(const Symbol *symbol)
{
    return this->_referencetable.referencesCount(symbol);
}

u64 DisassemblerBase::locationIsString(address_t address, bool *wide) const
{
    u64 count = this->locationIsStringT<char>(address, ::isprint, ::isalnum);

    if(count == 1) // Try with wide strings
    {
        count = this->locationIsStringT<u16>(address, [](u16 wb) -> bool { u8 b1 = wb & 0xFF, b2 = (wb & 0xFF00) >> 8; return ::isprint(b1) && !b2; },
                                                      [](u16 wb) -> bool { u8 b1 = wb & 0xFF, b2 = (wb & 0xFF00) >> 8; return ::isalnum(b1) && !b2; } );

        if(wide)
            *wide = true;
    }

    return count;
}

std::string DisassemblerBase::readString(const Symbol *symbol) const
{
    address_t memaddress = 0;

    if(symbol->is(SymbolTypes::Pointer) && this->dereferencePointer(symbol->address, memaddress))
        return this->readString(memaddress);

    return this->readString(symbol->address);
}

std::string DisassemblerBase::readWString(const Symbol *symbol) const
{
    address_t memaddress = 0;

    if(symbol->is(SymbolTypes::Pointer) && this->dereferencePointer(symbol->address, memaddress))
        return this->readWString(memaddress);

    return this->readWString(symbol->address);
}

Symbol *DisassemblerBase::dereferenceSymbol(const Symbol *symbol, u64* value)
{
    address_t a = 0;
    Symbol* ptrsymbol = NULL;

    if(symbol->is(SymbolTypes::Pointer) && this->dereferencePointer(symbol->address, a))
        ptrsymbol = this->_symboltable.symbol(a);

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
        LOG("Invalid size: " + std::to_string(size));
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
