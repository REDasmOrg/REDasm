#include "disassembler.h"
#include <algorithm>
#include <memory>

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
        REDasm::status("DONE");
        return;
    }

    address_t address = algorithm->next();
    InstructionPtr instruction = std::make_shared<Instruction>();
    u32 status = algorithm->disassemble(address, instruction);

    if(status == DisassemblerAlgorithm::SKIP)
        return;

    m_document->instruction(instruction);
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
    std::cout << m_timer.running() << std::endl;

    if(m_timer.running())
        return;

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
