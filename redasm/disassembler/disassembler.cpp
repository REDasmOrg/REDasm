#include "disassembler.h"
#include <algorithm>
#include <memory>
#include <cctype>

#define INVALID_MNEMONIC "db"
#define BRANCH_DIRECTION(instruction, destination) (static_cast<s64>(destination) - static_cast<s64>(instruction->address))

#define STATUS(s) if(_statuscallback) _statuscallback((s));
#define LOG(s)    if(_logcallback) _logcallback((s));

namespace REDasm {

Disassembler::Disassembler(Buffer buffer, ProcessorPlugin *processor, FormatPlugin *format): _processor(processor), _format(format), _buffer(buffer)
{
    this->_symboltable = format->symbols(); // Initialize symbol table

    this->_printer = PrinterPtr(this->_processor->createPrinter(&this->_symboltable));

    this->_listing.setFormat(this->_format);
    this->_listing.setProcessor(this->_processor);
    this->_listing.setSymbolTable(&this->_symboltable);
    this->_listing.setReferenceTable(&this->_referencetable);
}

Disassembler::~Disassembler()
{
    delete this->_processor;
    delete this->_format;
}

void Disassembler::loggerCallback(const Disassembler::ReportCallback &cb)
{
    this->_logcallback = cb;
}

void Disassembler::statusCallback(const Disassembler::ReportCallback &cb)
{
    this->_statuscallback = cb;
}

std::string Disassembler::readString(address_t address) const
{
    return this->readStringT<char>(address, [](char b, std::string& s) {
        bool r = ::isprint(b);
        if(r) s += b;
        return r;
    });
}

std::string Disassembler::readWString(address_t address) const
{
    return this->readStringT<u16>(address, [](u16 wb, std::string& s) {
        u8 b1 = wb & 0xFF, b2 = (wb & 0xFF00) >> 8;
        bool r = ::isprint(b1) && !b2;
        if(r) s += static_cast<char>(b1);
        return r;
    });
}

Listing& Disassembler::listing()
{
    return this->_listing;
}

Buffer &Disassembler::buffer()
{
    return this->_buffer;
}

std::string Disassembler::out(const InstructionPtr &instruction, std::function<void (const Operand &, const std::string&)> opfunc)
{
    if(this->_printer)
        return this->_printer->out(instruction, opfunc);

    return std::string();
}

std::string Disassembler::out(const InstructionPtr &instruction)
{
    if(this->_printer)
        return this->_printer->out(instruction);

    return std::string();
}

std::string Disassembler::comment(const InstructionPtr &instruction) const
{
     std::string res;

     std::for_each(instruction->comments.cbegin(), instruction->comments.cend(), [&res](const std::string& s) {
         if(!res.empty())
             res += " | ";

         res += s;
     });

     return "# " + res;
}

bool Disassembler::dataToString(address_t address)
{
    REDasm::Symbol* symbol = this->_symboltable.symbol(address);

    if(!symbol)
        return false;

    bool wide = false;
    this->locationIsString(address, &wide);

    std::string s;
    ReferenceVector refs = this->_referencetable.referencesToVector(symbol);

    symbol->type &= (~REDasm::SymbolTypes::Data);
    symbol->type |= wide ? REDasm::SymbolTypes::WideString : REDasm::SymbolTypes::String;;

    if(wide)
    {
        symbol->type |= REDasm::SymbolTypes::WideString;
        s = this->readWString(address);
    }
    else
    {
        symbol->type |= REDasm::SymbolTypes::String;
        s = this->readString(address);
    }

    std::for_each(refs.begin(), refs.end(), [s, wide](InstructionPtr& instruction) {
        wide ? instruction->cmt("UNICODE: " + s) : instruction->cmt("STRING: " + s);
    });

    return this->_symboltable.rename(symbol, "str_" + REDasm::hex(address, 0, false));
}

void Disassembler::disassembleFunction(address_t address)
{
    Symbol* symbol = this->_symboltable.symbol(address);

    if(!symbol || symbol->isFunction())
        return;

    this->_symboltable.erase(address);
    this->_symboltable.createFunction(address);
    this->disassemble(address);

    STATUS("Analyzing...");
    Analyzer analyzer;
    analyzer.analyze(this->_listing); // Run basic analyzer
}

void Disassembler::disassemble()
{
    // Preload format functions for analysis
    this->_symboltable.iterate(SymbolTypes::Function, [this](Symbol* symbol) -> bool {
        this->disassemble(symbol->address);
        return true;
    });

    std::unique_ptr<Analyzer> a(this->_format->createAnalyzer());

    if(a)
    {
        a->initCallbacks( [this](address_t address) -> InstructionPtr { Buffer b = this->_buffer + this->_format->offset(address); return this->disassembleInstruction(address, b); },
                          [this](address_t address) { this->disassemble(address); },
                          [this](address_t address, size_t size, u64& value) -> bool { return this->readAddress(address, size, value); });

        STATUS("Analyzing...");
        a->analyze(this->_listing);
    }

    this->_symboltable.sort();
}

bool Disassembler::dereferencePointer(address_t address, u64 &value) const
{
    return this->readAddress(address, this->_format->bits() / 8, value);
}

bool Disassembler::readAddress(address_t address, size_t size, u64& value) const
{
    if(!this->_format->segment(address))
        return false;

    offset_t offset = this->_format->offset(address);
    return this->readOffset(offset, size, value);
}

bool Disassembler::readOffset(offset_t offset, size_t size, u64 &value) const
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

u64 Disassembler::locationIsString(address_t address, bool* wide) const
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

std::string Disassembler::readString(const Symbol *symbol) const
{
    address_t memaddress = 0;

    if(symbol->is(SymbolTypes::Pointer) && this->dereferencePointer(symbol->address, memaddress))
        return this->readString(memaddress);

    return this->readString(symbol->address);
}

std::string Disassembler::readWString(const Symbol *symbol) const
{
    address_t memaddress = 0;

    if(symbol->is(SymbolTypes::Pointer) && this->dereferencePointer(symbol->address, memaddress))
        return this->readWString(memaddress);

    return this->readWString(symbol->address);
}

void Disassembler::checkJumpTable(const InstructionPtr &instruction, const Operand& op)
{
    bool isjumptable = false;
    size_t cases = 0;
    address_t address = op.mem.displacement, target = 0;

    this->_symboltable.createLocation(address, SymbolTypes::Data);
    Symbol* jmpsymbol = this->_symboltable.symbol(address);

    while(this->readAddress(address, op.mem.scale, target))
    {
        Segment* segment = this->_format->segment(target);

        if(!segment || !segment->is(SegmentTypes::Code))
            break;

        isjumptable = true;
        this->disassemble(target);

        if(this->_symboltable.createLocation(target, SymbolTypes::Code))
        {
            Symbol* symbol = this->_symboltable.symbol(target);
            auto it = this->_listing.find(target);

            if(it != this->_listing.end())
            {
                InstructionPtr& tgtinstruction = it->second;
                tgtinstruction->cmt("JUMP_TABLE @ " + REDasm::hex(instruction->address) + " case " + std::to_string(cases));
                this->_referencetable.push(jmpsymbol, tgtinstruction);
            }

            if(symbol)
                this->_referencetable.push(symbol, instruction);
        }

        address += op.mem.scale;
        cases++;
    }

    if(isjumptable)
        instruction->cmt("#" + std::to_string(cases) + " case(s) jump table");
}

bool Disassembler::analyzeTarget(const InstructionPtr &instruction)
{
    int index = -1;
    address_t target = 0;

    if(!this->_processor->target(instruction, &target, &index))
        return false;

    const Segment* segment = this->_format->segment(target);

    if(!segment)
        return false;

    if(instruction->is(InstructionTypes::Jump))
    {
        const Operand& op = instruction->operands[index];

        if(!op.is(OperandTypes::Displacement) || op.mem.displacementOnly())
        {
            this->_symboltable.createLocation(target, (segment->is(SegmentTypes::Code) ? SymbolTypes::Code :
                                                                                         SymbolTypes::Data));

            int dir = BRANCH_DIRECTION(instruction, target);

            if(dir < 0)
                instruction->cmt("Possible loop");
            else if(!dir)
                instruction->cmt("Infinite loop");
        }
        else
            this->checkJumpTable(instruction, op);
    }
    else if(instruction->is(InstructionTypes::Call))
        this->_symboltable.createFunction(target);
    else
        return false;

    Symbol* symbol = this->_symboltable.symbol(target);

    if(symbol)
        this->_referencetable.push(symbol, instruction);

    return true;
}

void Disassembler::analyzeOp(const InstructionPtr &instruction, const Operand &operand)
{
    if(operand.is(OperandTypes::Register))
        return;

    u64 value = operand.is(OperandTypes::Displacement) ? operand.mem.displacement : operand.u_value, memvalue = value;
    Symbol* symbol = this->_symboltable.symbol(value);

    if(operand.is(OperandTypes::Memory))
        this->dereferencePointer(value, memvalue); // Try to read pointed memory

    const Segment* segment = this->_format->segment(value);

    if(!segment)
        return;

    if(!symbol || !symbol->isFunction())
    {
        bool wide = false;

        if(!segment->is(SegmentTypes::Bss) && (this->locationIsString(memvalue, &wide) >= MIN_STRING))
        {
            if(wide)
            {
                this->_symboltable.createWString(value);
                instruction->cmt("UNICODE: " + this->readWString(memvalue));
            }
            else
            {
                this->_symboltable.createString(value);
                instruction->cmt("STRING: " + this->readString(memvalue));
            }
        }
        else
            this->_symboltable.createLocation(value, segment->is(SegmentTypes::Code) ? SymbolTypes::Code :
                                                                                       SymbolTypes::Data);
        symbol = this->_symboltable.symbol(value);

        if(symbol && operand.is(OperandTypes::Memory))
            symbol->type |= SymbolTypes::Pointer;
    }

    if(symbol)
        this->_referencetable.push(symbol, instruction);
}

void Disassembler::disassemble(address_t address)
{
    address_t target = 0;
    const Segment* segment = this->_format->segment(address);

    this->_processor->pushState();

    while(segment && segment->is(SegmentTypes::Code)) // Don't disassemble data/junk
    {
        if(this->_listing.find(address) != this->_listing.end())
            break;

        Buffer b = this->_buffer + this->_format->offset(address);
        InstructionPtr instruction = this->disassembleInstruction(address, b);

        if(this->_processor->target(instruction, &target))
            this->disassemble(target);

        if(this->_processor->done(instruction))
            break;

        address += instruction->size;
        segment = this->_format->segment(address);
    }

    this->_processor->popState();
}

InstructionPtr Disassembler::disassembleInstruction(address_t address, Buffer& b)
{
    InstructionPtr instruction = std::make_shared<Instruction>();
    instruction->address = address;

    STATUS("Disassembling " + REDasm::hex(address));

    if(!this->_processor->decode(b, instruction))
    {
        instruction->type = InstructionTypes::Invalid;
        instruction->mnemonic = INVALID_MNEMONIC;
        instruction->size = 1;
        instruction->imm(static_cast<u64>(*b));

        LOG("Invalid instruction at " + REDasm::hex(address));
    }
    else if(!this->analyzeTarget(instruction))
    {
        const OperandList& operands = instruction->operands;

        std::for_each(operands.begin(), operands.end(), [this, instruction](const Operand& operand) {
            this->analyzeOp(instruction, operand);
        });
    }

    this->_listing[address] = instruction;
    return instruction;
}

FormatPlugin *Disassembler::format()
{
    return this->_format;
}

ProcessorPlugin *Disassembler::processor()
{
    return this->_processor;
}

SymbolTable *Disassembler::symbols()
{
    return &this->_symboltable;
}

ReferenceTable *Disassembler::references()
{
    return &this->_referencetable;
}

}
