#include "disassemblerbase.h"
#include <cctype>

namespace REDasm {

DisassemblerBase::DisassemblerBase(FormatPlugin *format): DisassemblerAPI(), m_format(format) { m_document = format->document(); }
DisassemblerBase::~DisassemblerBase() { delete m_format; }
ReferenceVector DisassemblerBase::getReferences(address_t address) { return m_referencetable.referencesToVector(address); }

ReferenceVector DisassemblerBase::getReferences(const SymbolPtr& symbol)
{
    if(symbol->is(SymbolTypes::Pointer))
    {
        SymbolPtr ptrsymbol = this->dereferenceSymbol(symbol);

        if(ptrsymbol)
            return m_referencetable.referencesToVector(ptrsymbol->address);
    }

    return m_referencetable.referencesToVector(symbol->address);
}

u64 DisassemblerBase::getReferencesCount(address_t address) { return m_referencetable.referencesCount(address); }

u64 DisassemblerBase::getReferencesCount(const SymbolPtr &symbol)
{
    if(symbol->is(SymbolTypes::Pointer))
    {
        SymbolPtr ptrsymbol = this->dereferenceSymbol(symbol);

        if(ptrsymbol)
            return m_referencetable.referencesCount(ptrsymbol->address);
    }

    return m_referencetable.referencesCount(symbol->address);
}

bool DisassemblerBase::hasReferences(const SymbolPtr& symbol)
{
    if(symbol->is(SymbolTypes::Pointer))
    {
        SymbolPtr ptrsymbol = this->dereferenceSymbol(symbol);

        if(ptrsymbol)
            return m_referencetable.hasReferences(ptrsymbol->address);
    }

    return m_referencetable.hasReferences(symbol->address);
}

void DisassemblerBase::pushReference(const SymbolPtr &symbol, const InstructionPtr& refbyinstruction)
{
    m_referencetable.push(symbol->address, refbyinstruction->address);
}

void DisassemblerBase::pushReference(address_t address, const InstructionPtr& refbyinstruction)
{
    m_referencetable.push(address, refbyinstruction->address);
}

void DisassemblerBase::checkLocation(const InstructionPtr &instruction, address_t address)
{
    u64 target = address, stringscount = 0;

    while(this->dereference(target, &target))
    {
        if(!this->checkString(instruction, target))
            break;

        stringscount++;
        target = address + (stringscount * m_format->addressWidth());
    }

    if(!stringscount)
    {
        if(!this->checkString(instruction, address))
            m_document->symbol(address, SymbolTypes::Data);
    }
    else
        m_document->symbol(address, SymbolTypes::Data | SymbolTypes::Pointer);

    this->pushReference(address, instruction);
}

bool DisassemblerBase::checkString(const InstructionPtr &instruction, address_t address)
{
    bool wide = false;

    if(this->locationIsString(address, &wide) < MIN_STRING)
        return false;

    if(wide)
    {
        m_document->symbol(address, SymbolTypes::WideString);
        m_document->comment(instruction, "WIDE STRING: " + REDasm::quoted(this->readWString(address)));
    }
    else
    {
        m_document->symbol(address, SymbolTypes::String);
        m_document->comment(instruction, "STRING: " + REDasm::quoted(this->readString(address)));
    }

    this->pushReference(address, instruction);
    return true;
}

int DisassemblerBase::checkAddressTable(const InstructionPtr &instruction, address_t startaddress)
{
    address_t target = 0, address = startaddress;

    if(!this->readAddress(address, m_format->addressWidth(), &target))
        return 0;

    REDasm::status("Checking address table @ " + REDasm::hex(startaddress, m_format->bits(), false));
    int c = 0;

    while(this->readAddress(address, m_format->addressWidth(), &target))
    {
        const Segment* segment = m_document->segment(target);

        if(!segment || !segment->is(SegmentTypes::Code))
            break;

        instruction->target(target);
        address += m_format->addressWidth();
        c++;
    }

    if(c)
    {
        this->pushReference(startaddress, instruction);
        m_document->update(instruction);

        if(c > 1)
            m_document->table(startaddress, c);
        else
            m_document->pointer(startaddress, SymbolTypes::Data);
    }

    return c;
}

FormatPlugin *DisassemblerBase::format() { return m_format; }
ListingDocument *DisassemblerBase::document() { return m_document; }

u64 DisassemblerBase::locationIsString(address_t address, bool *wide) const
{
    Segment* segment = m_document->segment(address);

    if(!segment || segment->is(SegmentTypes::Bss))
        return 0;

    if(wide)
        *wide = false;

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

    if(symbol->is(SymbolTypes::Pointer) && this->dereference(symbol->address, &memaddress))
        return this->readString(memaddress);

    return this->readString(symbol->address);
}

std::string DisassemblerBase::readWString(const SymbolPtr &symbol) const
{
    address_t memaddress = 0;

    if(symbol->is(SymbolTypes::Pointer) && this->dereference(symbol->address, &memaddress))
        return this->readWString(memaddress);

    return this->readWString(symbol->address);
}

std::string DisassemblerBase::readHex(address_t address, u32 count) const
{
    Buffer data;

    if(!this->getBuffer(address, data))
        return std::string();

    count = std::min(static_cast<s64>(count), m_format->buffer().length);

    std::stringstream ss;
    ss << std::hex << std::setfill('0');

    for(u64 i = 0; i < count; i++)
        ss << std::uppercase << std::setw(2) << static_cast<size_t>(data[i]);

    return ss.str();
}

SymbolPtr DisassemblerBase::dereferenceSymbol(const SymbolPtr& symbol, u64* value)
{
    address_t address = 0;
    SymbolPtr ptrsymbol;

    if(symbol->is(SymbolTypes::Pointer) && this->dereference(symbol->address, &address))
        ptrsymbol = m_document->symbol(address);

    if(value)
        *value = address;

    return ptrsymbol;
}

bool DisassemblerBase::dereference(address_t address, u64 *value) const
{
    if(!value)
        return false;

    return this->readAddress(address, m_format->addressWidth(), value);
}

bool DisassemblerBase::readAddress(address_t address, size_t size, u64 *value) const
{
    if(!value)
        return false;

    Segment* segment = m_document->segment(address);

    if(!segment || segment->is(SegmentTypes::Bss))
        return false;

    return this->readOffset(m_format->offset(address), size, value);
}

bool DisassemblerBase::getBuffer(address_t address, Buffer &data) const
{
    Segment* segment = m_document->segment(address);

    if(!segment || segment->is(SegmentTypes::Bss))
        return false;

    data = m_format->buffer() + m_format->offset(address);
    return true;
}

bool DisassemblerBase::readOffset(offset_t offset, size_t size, u64 *value) const
{
    if(!value)
        return false;

    Buffer pdest = m_format->buffer() + offset;

    if(size == 1)
        *value = *reinterpret_cast<u8*>(pdest.data);
    else if(size == 2)
        *value = *reinterpret_cast<u16*>(pdest.data);
    else if(size == 4)
        *value = *reinterpret_cast<u32*>(pdest.data);
    else if(size == 8)
        *value = *reinterpret_cast<u64*>(pdest.data);
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
