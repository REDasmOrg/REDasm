#include "disassembler.h"
#include <algorithm>
#include <memory>

#define INVALID_MNEMONIC       "db"
#define INSTRUCTION_THRESHOLD  10
#define DO_TICK_DISASSEMBLY()  m_timer.tick(std::bind(&Disassembler::disassembleStep, this, m_algorithm.get()))

namespace REDasm {

Disassembler::Disassembler(AssemblerPlugin *assembler, FormatPlugin *format): DisassemblerBase(format)
{
    if(!format->isBinary())
        assembler->setEndianness(format->endianness());

    m_assembler = std::make_unique<AssemblerPlugin>(assembler);
    m_algorithm = std::make_unique<DisassemblerAlgorithm>(m_format->createAlgorithm(this, assembler));
}

Disassembler::~Disassembler() { }
ListingDocument *Disassembler::document() { return m_document; }

size_t Disassembler::walkJumpTable(const InstructionPtr &instruction, address_t address)
{
    address_t target = 0;
    size_t cases = 0, sz = m_format->addressWidth();
    SymbolPtr jmpsymbol = m_document->symbol(address);

    while(this->readAddress(address, sz, &target))
    {
        const Segment* segment = m_document->segment(target);

        if(!segment || !segment->is(SegmentTypes::Code))
            break;

        instruction->target(target);
        m_document->symbol(target, SymbolTypes::Code);

        /*
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
        */
    }

    if(cases)
    {
        instruction->type |= InstructionTypes::JumpTable;
        instruction->cmt("#" + std::to_string(cases) + " case(s) jump table");
        //this->_listing.update(instruction);
    }

    return cases;
}

void Disassembler::disassembleStep(DisassemblerAlgorithm* algorithm)
{
    if(!algorithm->hasNext())
    {
        m_timer.stop();
        algorithm->analyze();
        return;
    }

    address_t address = algorithm->next();
    InstructionPtr instruction = std::make_shared<Instruction>();
    u32 status = algorithm->disassemble(address, instruction);

    if(status == DisassemblerAlgorithm::SKIP)
        return;

    m_document->instruction(instruction);
}

void Disassembler::disassembleUnexploredCode()
{
    /*
    for(auto it = m_document->segments().begin(); it != m_document->segments().end(); it++)
    {
        const Segment& segment = *it;

        if(!segment.is(SegmentTypes::Code))
            continue;

        this->searchStrings(segment);
        this->searchCode(segment);
    }
    */
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

        //this->disassembleFunction(address);
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
                m_document->symbol(address, SymbolTypes::WideString);
                address += this->readWString(address).size() * sizeof(u16);
            }
            else
            {
                m_document->symbol(address, SymbolTypes::String);
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
    SymbolPtr symbol = m_document->symbol(address);

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

    /*
    if(symbol->isFunction())
    {
        if(!this->_listing.getFunctionBounds(address, NULL, &address))
            address++;

        return true;
    }
    */

    if(symbol->is(SymbolTypes::Pointer))
    {
        address += this->m_format->addressWidth();
        return true;
    }

    return false;
}

bool Disassembler::skipPadding(address_t &address)
{
    address_t startaddress = address;
    u64 value = 0;

    while(this->readAddress(address, this->m_format->addressWidth(), &value) && !value)
        address += this->m_format->addressWidth();

    return address != startaddress;
}

bool Disassembler::maybeValidCode(address_t& address)
{
    /*
    auto it = this->_listing.find(address);

    if(it != this->_listing.end())
    {
        address += (*it)->size;
        return false;
    }

    u64 value = 0;

    if(!this->readAddress(address, this->m_format->addressWidth(), &value)) // Check for address
    {
        address++;
        return false;
    }

    Segment* segment = this->m_format->segment(value); // Check if this value points somewhere

    if(!segment)
    {
        address_t caddress = address;
        InstructionPtr instruction;

        for(u32 i = 0; i < INSTRUCTION_THRESHOLD; i++) // Try to disassemble some instructions
        {
            if(this->skipExploredData(caddress) || !this->m_format->segment(caddress))
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

    address += this->m_format->addressWidth();
    */

    return false;
}

void Disassembler::disassemble()
{
    SymbolTable* symboltable = m_document->symbols();
    SymbolPtr entrypoint = symboltable->entryPoint();

    // Preload format functions for analysis
    symboltable->iterate(SymbolTypes::FunctionMask, [=](SymbolPtr symbol) -> bool {
        m_algorithm->push(symbol->address);
        return true;
    });

    if(entrypoint)
        m_algorithm->push(entrypoint->address); // Push entry point

    DO_TICK_DISASSEMBLY();

    /*
    // Analyze and disassemble unexplored bytes in code sections
    if(!(this->_format->flags() & FormatFlags::IgnoreUnexploredCode))
    {
        REDasm::status("Looking for missing code...");
        this->disassembleUnexploredCode();
    }
    */
}

AssemblerPlugin *Disassembler::assembler() { return m_assembler.get(); }

bool Disassembler::checkJumpTable(const InstructionPtr &instruction, address_t address)
{
    /*
    address_t target = 0;
    size_t cases = 0, sz = this->m_format->bits() / 8;
    SymbolPtr jmpsymbol = this->_symboltable->symbol(address);

    while(this->readAddress(address, sz, &target))
    {
        Segment* segment = this->m_format->segment(target);

        if(!segment || !segment->is(SegmentTypes::Code))
            break;

        instruction->target(target);

        if(instruction->is(InstructionTypes::Call))
        {
            if(segment != this->m_format->entryPointSegment())
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
    */
}

void Disassembler::disassemble(address_t address)
{
    m_algorithm->push(address);
    DO_TICK_DISASSEMBLY();
}

InstructionPtr Disassembler::disassembleInstruction(address_t address)
{
    InstructionPtr instruction = m_document->instruction(address);

    if(instruction)
        return instruction;

    instruction = std::make_shared<Instruction>();
    m_algorithm->disassembleSingle(address, instruction);
    return instruction;
}

}
