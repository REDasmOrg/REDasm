#include "disassembler.h"
#include <algorithm>
#include <memory>

#define INVALID_MNEMONIC      "db"
#define INSTRUCTION_THRESHOLD 10

namespace REDasm {

Disassembler::Disassembler(Buffer buffer, AssemblerPlugin *assembler, FormatPlugin *format): DisassemblerBase(buffer, format), _assembler(assembler)
{
    if(!format->isBinary())
        assembler->setEndianness(format->endianness());

    this->_printer = PrinterPtr(this->_assembler->createPrinter(this, this->_symboltable));
    this->_emulator = assembler->hasVMIL() ? assembler->createEmulator(this) : NULL;

    this->_listing.setFormat(this->_format);
    this->_listing.setAssembler(this->_assembler);
    this->_listing.setSymbolTable(this->_symboltable);
    this->_listing.setReferenceTable(&this->_referencetable);
}

Disassembler::~Disassembler()
{
    if(this->_emulator)
        delete this->_emulator;

    delete this->_assembler;
}

InstructionsPool& Disassembler::instructions()
{
    return this->_listing;
}

size_t Disassembler::walkJumpTable(const InstructionPtr &instruction, address_t address)
{
    address_t target = 0;
    size_t cases = 0, sz = this->_format->bits() / 8;
    SymbolPtr jmpsymbol = this->_symboltable->symbol(address);

    while(this->readAddress(address, sz, &target))
    {
        Segment* segment = this->_format->segment(target);

        if(!segment || !segment->is(SegmentTypes::Code))
            break;

        instruction->target(target);
        this->_symboltable->createLocation(target, SymbolTypes::Code);
        auto it = this->_listing.find(target);

        if(it != this->_listing.end())
        {
            InstructionPtr tgtinstruction = *it;
            tgtinstruction->cmt("JUMP_TABLE @ " + REDasm::hex(instruction->address) + " case " + std::to_string(cases));
            this->_listing.update(tgtinstruction);
            this->pushReference(jmpsymbol, tgtinstruction);
        }

        this->pushReference(target, instruction);
        address += sz;
        cases++;
    }

    if(cases)
    {
        instruction->type |= InstructionTypes::JumpTable;
        instruction->cmt("#" + std::to_string(cases) + " case(s) jump table");
        this->_listing.update(instruction);
    }

    return cases;
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

bool Disassembler::iterateVMIL(address_t address, InstructionsPool::InstructionCallback cbinstruction, InstructionsPool::SymbolCallback cbstart, InstructionsPool::InstructionCallback cbend, InstructionsPool::SymbolCallback cblabel)
{
    std::unique_ptr<VMIL::Emulator> emulator(this->_assembler->createEmulator(this));

    if(!emulator)
        return false;

    return this->_listing.iterateFunction(address, [this, &emulator, &cbinstruction](const InstructionPtr& instruction) {
        VMIL::VMILInstructionList vminstructions;
        emulator->translate(instruction, vminstructions);

        std::for_each(vminstructions.begin(), vminstructions.end(), [cbinstruction](const VMIL::VMILInstructionPtr& vminstruction) {
           cbinstruction(vminstruction);
        });

    }, cbstart, cbend, cblabel);
}

void Disassembler::disassemble(DisassemblerAlgorithm* algorithm)
{
    Segment* segment = NULL;

    while(algorithm->hasNext())
    {
        address_t address = algorithm->next();

        if(!segment || !segment->contains(address))
            segment = this->_format->segment(address);

        if(!segment || !segment->is(SegmentTypes::Code))
            continue;

        Buffer buffer = this->_buffer + this->_format->offset(address);

        if(buffer.eob())
            continue;

        InstructionPtr instruction = std::make_shared<Instruction>();
        instruction->address = address;

        REDasm::status("Disassembling @ " + REDasm::hex(address, this->_format->bits(), false));
        u32 status = algorithm->disassemble(buffer, instruction);

        if(status == DisassemblerAlgorithm::FAIL)
            this->createInvalid(instruction, buffer);

        this->_listing.commit(instruction->address, instruction);
    }

    std::unique_ptr<Analyzer> a(this->_format->createAnalyzer(this, this->_format->signatures()));

    if(a)
    {
        REDasm::status("Analyzing...");
        a->analyze(this->_listing);
    }

    REDasm::status("Sorting symbols...");
    this->_symboltable->sort();

    REDasm::status("Calculating bounds...");
    this->calculateBounds();
}

void Disassembler::disassembleUnexploredCode()
{
    for(auto it = this->_format->segments().begin(); it != this->_format->segments().end(); it++)
    {
        const Segment& segment = *it;

        if(!segment.is(SegmentTypes::Code))
            continue;

        this->searchStrings(segment);
        this->searchCode(segment);
    }
}

void Disassembler::searchCode(const Segment &segment)
{
    address_t address = segment.address;

    while(address < segment.endaddress)
    {
        REDasm::status("Searching code @ " + REDasm::hex(address));

        if(this->skipExploredData(address))
            continue;

        if(this->skipPadding(address))
            continue;

        if(!this->maybeValidCode(address))
            continue;

        this->disassembleFunction(address);
    }
}

void Disassembler::searchStrings(const Segment &segment)
{
    address_t address = segment.address;
    u64 value = 0;
    bool wide = false;

    while(address < segment.endaddress)
    {
        REDasm::status("Searching strings @ " + REDasm::hex(address));

        if(this->skipExploredData(address))
            continue;

        if(this->locationIsString(address, &wide) >= MIN_STRING)
        {
            if(wide)
            {
                this->_symboltable->createWString(address);
                address += this->readWString(address).size() * sizeof(u16);
            }
            else
            {
                this->_symboltable->createString(address);
                address += this->readString(address).size();
            }

            if(this->readAddress(address, wide ? sizeof(u16) : sizeof(char), &value) && !value) // Check for null terminator
                address += (wide ? sizeof(u16) : sizeof(char));

            continue;
        }

        address++;
    }
}

bool Disassembler::skipExploredData(address_t &address)
{
    SymbolPtr symbol = this->_symboltable->symbol(address);

    if(!symbol)
        return false;

    if(symbol->is(SymbolTypes::String))
    {
        u64 value = 0;
        bool wide = false;

        this->locationIsString(address, &wide);

        if(wide)
            address += this->readWString(symbol).size() * sizeof(u16);
        else
            address += this->readString(symbol).size();

        if(this->readAddress(address, wide ? sizeof(u16) : sizeof(char), &value) && !value) // Check for null terminator
            address += (wide ? sizeof(u16) : sizeof(char));

        return true;
    }

    if(symbol->isFunction())
    {
        if(!this->_listing.getFunctionBounds(address, NULL, &address))
            address++;

        return true;
    }

    if(symbol->is(SymbolTypes::Pointer))
    {
        address += this->_format->addressWidth();
        return true;
    }

    return false;
}

bool Disassembler::skipPadding(address_t &address)
{
    address_t startaddress = address;
    u64 value = 0;

    while(this->readAddress(address, this->_format->addressWidth(), &value) && !value)
        address += this->_format->addressWidth();

    return address != startaddress;
}

bool Disassembler::maybeValidCode(address_t& address)
{
    auto it = this->_listing.find(address);

    if(it != this->_listing.end())
    {
        address += (*it)->size;
        return false;
    }

    u64 value = 0;

    if(!this->readAddress(address, this->_format->addressWidth(), &value)) // Check for address
    {
        address++;
        return false;
    }

    Segment* segment = this->_format->segment(value); // Check if this value points somewhere

    if(!segment)
    {
        address_t caddress = address;
        InstructionPtr instruction;

        for(u32 i = 0; i < INSTRUCTION_THRESHOLD; i++) // Try to disassemble some instructions
        {
            if(this->skipExploredData(caddress) || !this->_format->segment(caddress))
            {
                address = caddress;
                return false;
            }

            instruction = this->disassembleInstruction(caddress);
            caddress += instruction->size ? instruction->size : 1;

            if(instruction->isInvalid())
            {
                address++;
                return false;
            }
        }

        return true;
    }

    address += this->_format->addressWidth();
    return false;
}

bool Disassembler::disassembleFunction(address_t address, const std::string &name)
{
    Segment* segment = this->_format->segment(address);

    if(!segment || !segment->is(SegmentTypes::Code))
        return false;

    SymbolPtr symbol = this->_symboltable->symbol(address);

    if(symbol && symbol->isFunction())
    {
        if(!name.empty() && !symbol->isLocked())
            this->_symboltable->update(symbol, name);

        return true;
    }

    auto it = this->_listing.find(address);

    if(it != this->_listing.end())
    {
        it--;

        if(it != this->_listing.end())
            this->_listing.stopFunctionAt(*it); // Stop function @ previous address, if any
    }

    this->_symboltable->erase(address);

    if(name.empty())
    {
        if(segment != this->_format->entryPointSegment())
            this->_symboltable->createFunction(address, segment);
        else
            this->_symboltable->createFunction(address);
    }
    else
        this->_symboltable->createFunction(address, name);

    this->disassemble(address);
    this->_listing.checkBounds(address);
    return true;
}

void Disassembler::disassemble()
{
    return; //FIXME: !!!
    std::unique_ptr<DisassemblerAlgorithm> algorithm(this->_format->createAlgorithm(this, this->_assembler));
    SymbolPtr entrypoint = this->_symboltable->entryPoint();

    if(entrypoint)
        algorithm->push(entrypoint->address); // Push entry point

    // Preload format functions for analysis
    this->_symboltable->iterate(SymbolTypes::FunctionMask, [&algorithm](SymbolPtr symbol) -> bool {
        algorithm->push(symbol->address);
        return true;
    });

    this->disassemble(algorithm.get());

    /*
    // Analyze and disassemble unexplored bytes in code sections
    if(!(this->_format->flags() & FormatFlags::IgnoreUnexploredCode))
    {
        REDasm::status("Looking for missing code...");
        this->disassembleUnexploredCode();
    }
    */

    REDasm::status("Marking Entry Point...");
    this->_listing.markEntryPoint();
}


AssemblerPlugin *Disassembler::assembler()
{
    return this->_assembler;
}

VMIL::Emulator *Disassembler::emulator()
{
    return this->_emulator;
}

void Disassembler::updateInstruction(const InstructionPtr &instruction)
{
    this->_listing.update(instruction);
}

bool Disassembler::dataToString(address_t address)
{
    SymbolPtr symbol = this->_symboltable->symbol(address);

    if(!symbol)
        return false;

    bool wide = false;
    this->locationIsString(address, &wide);

    std::string s;
    ReferenceVector refs = this->_referencetable.referencesToVector(symbol->address);

    symbol->type &= (~SymbolTypes::Data);
    symbol->type |= wide ? SymbolTypes::WideString : SymbolTypes::String;

    if(wide)
    {
        symbol->type |= SymbolTypes::WideString;
        s = REDasm::quoted(this->readWString(address));
    }
    else
    {
        symbol->type |= SymbolTypes::String;
        s = REDasm::quoted(this->readString(address));
    }

    std::for_each(refs.begin(), refs.end(), [this, s, wide](address_t address) {
        InstructionPtr instruction = this->_listing[address];
        wide ? instruction->cmt("UNICODE: " + s) : instruction->cmt("STRING: " + s);
        this->_listing.update(instruction);
    });

    return this->_symboltable->update(symbol, "str_" + REDasm::hex(address, 0, false));
}

bool Disassembler::checkJumpTable(const InstructionPtr &instruction, address_t address)
{
    address_t target = 0;
    size_t cases = 0, sz = this->_format->bits() / 8;
    SymbolPtr jmpsymbol = this->_symboltable->symbol(address);

    while(this->readAddress(address, sz, &target))
    {
        Segment* segment = this->_format->segment(target);

        if(!segment || !segment->is(SegmentTypes::Code))
            break;

        instruction->target(target);

        if(instruction->is(InstructionTypes::Call))
        {
            if(segment != this->_format->entryPointSegment())
                this->_symboltable->createFunction(target, segment);
            else
                this->_symboltable->createFunction(target);
        }
        else
            this->_symboltable->createLocation(target, SymbolTypes::Code);

        this->pushReference(target, instruction);
        address += sz;
        cases++;
    }

    if(cases)
    {
        instruction->type |= InstructionTypes::JumpTable;
        instruction->cmt("#" + std::to_string(cases) + " case(s) jump table");
    }

    return cases > 0;
}

void Disassembler::disassemble(address_t address)
{
    std::unique_ptr<DisassemblerAlgorithm> algorithm(this->_format->createAlgorithm(this, this->_assembler));
    algorithm->push(address);
    this->disassemble(algorithm.get());
}

InstructionPtr Disassembler::disassembleInstruction(address_t address)
{
    auto it = this->_listing.find(address);

    if(it != this->_listing.end())
        return *it;

    InstructionPtr instruction = std::make_shared<Instruction>();
    instruction->address = address;

    Buffer b = this->_buffer + this->_format->offset(instruction->address);

    if(b.eob() || !this->_assembler->decode(b, instruction))
        this->createInvalid(instruction, b);

    return instruction;
}

void Disassembler::createInvalid(const InstructionPtr &instruction, Buffer& b)
{
    if(!instruction->size)
        instruction->size = 1; // Invalid instruction uses at least 1 byte

    instruction->type = InstructionTypes::Invalid;
    instruction->mnemonic = INVALID_MNEMONIC;

    if(!instruction->bytes.empty())
        return;

    std::stringstream ss;
    ss << std::hex << *b;
    instruction->bytes = ss.str();
}

void Disassembler::calculateBounds()
{
    //TODO: !!!

}

}
