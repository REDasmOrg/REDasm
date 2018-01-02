#include "disassembler.h"
#include <algorithm>
#include <memory>

#define INVALID_MNEMONIC "db"

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

Listing& Disassembler::listing()
{
    return this->_listing;
}

bool Disassembler::canBeJumpTable(address_t address) const
{
    address_t cbaddress = 0;

    if(!this->readAddress(address, this->_format->bits() / 8, cbaddress))
        return false;

    Segment* segment = this->_format->segment(cbaddress);
    return segment && segment->is(SegmentTypes::Code);
}

size_t Disassembler::walkJumpTable(const InstructionPtr &instruction, address_t address, std::function<void(address_t)> cb)
{
    size_t cases = 0;
    address_t target = 0;
    size_t sz = this->_format->bits() / 8;
    SymbolPtr jmpsymbol = this->_symboltable->symbol(address);

    while(this->readAddress(address, sz, target))
    {
        Segment* segment = this->_format->segment(target);

        if(!segment || !segment->is(SegmentTypes::Code))
            break;

        instruction->target(target);
        cb(target);

        this->_symboltable->createLocation(target, SymbolTypes::Code);
        auto it = this->_listing.find(target);

        if(it != this->_listing.end())
        {
            InstructionPtr tgtinstruction = *it;
            tgtinstruction->cmt("JUMP_TABLE @ " + REDasm::hex(instruction->address) + " case " + std::to_string(cases));
            this->_listing.update(tgtinstruction);
            this->_referencetable.push(jmpsymbol, tgtinstruction->address);
        }

        SymbolPtr symbol = this->_symboltable->symbol(target);

        if(symbol)
            this->_referencetable.push(symbol, instruction->address);

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

bool Disassembler::iterateVMIL(address_t address, Listing::InstructionCallback cbinstruction, Listing::SymbolCallback cbstart, Listing::InstructionCallback cbend, Listing::SymbolCallback cblabel)
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

void Disassembler::disassembleFunction(address_t address)
{
    SymbolPtr symbol = this->_symboltable->symbol(address);

    if(symbol && symbol->isFunction())
        return;

    this->_symboltable->erase(address);
    this->_symboltable->createFunction(address);
    this->disassemble(address);

    REDasm::status("Analyzing...");
    Analyzer analyzer(this, this->_format->signatures());
    analyzer.analyze(this->_listing); // Run basic analyzer

    REDasm::status("Calculating paths...");
    this->_listing.calculatePaths();
}

void Disassembler::disassemble()
{
    SymbolPtr entrypoint = this->_symboltable->entryPoint();

    if(entrypoint)
        this->disassemble(entrypoint->address); // Disassemble entry point first

    // Preload format functions for analysis
    this->_symboltable->iterate(SymbolTypes::FunctionMask, [this](SymbolPtr symbol) -> bool {
        this->disassemble(symbol->address);
        return true;
    });

    std::unique_ptr<Analyzer> a(this->_format->createAnalyzer(this, this->_format->signatures()));

    REDasm::status("Calculating paths...");
    this->_listing.calculatePaths();

    if(a)
    {
        REDasm::status("Analyzing...");
        a->analyze(this->_listing);

        REDasm::status("Recalculating paths...");
        this->_listing.calculatePaths();
    }

    REDasm::status("Sorting symbols...");
    this->_symboltable->sort();

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
    ReferenceVector refs = this->_referencetable.referencesToVector(symbol);

    symbol->type &= (~SymbolTypes::Data);
    symbol->type |= wide ? SymbolTypes::WideString : SymbolTypes::String;

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

    std::for_each(refs.begin(), refs.end(), [this, s, wide](address_t address) {
        InstructionPtr instruction = this->_listing[address];
        wide ? instruction->cmt("UNICODE: " + s) : instruction->cmt("STRING: " + s);
        this->_listing.update(instruction);
    });

    return this->_symboltable->update(symbol, "str_" + REDasm::hex(address, 0, false));
}

InstructionPtr Disassembler::disassembleInstruction(address_t address)
{
    Buffer b = this->_buffer + this->_format->offset(address);
    return this->disassembleInstruction(address, b);
}

void Disassembler::checkJumpTable(const InstructionPtr &instruction, const Operand& operand)
{
    address_t address = operand.mem.displacement;
    this->_symboltable->createLocation(address, SymbolTypes::Data);

    if(!this->canBeJumpTable(address))
        return;

    this->walkJumpTable(instruction, address, [this](address_t target) {
       this->disassemble(target);
    });
}

bool Disassembler::disassemble(address_t address)
{
    const Segment* segment = this->_format->segment(address);

    if(!segment || !segment->is(SegmentTypes::Code))
        return false;

    this->_assembler->pushState();

    while(segment && segment->is(SegmentTypes::Code)) // Don't disassemble data (1)
    {
        if(this->_listing.find(address) != this->_listing.end())
            break;

        SymbolPtr symbol = this->_symboltable->symbol(address);

        if(symbol && !symbol->is(SymbolTypes::Code))  // Don't disassemble data (2)
            break;

        Buffer b = this->_buffer + this->_format->offset(address);
        InstructionPtr instruction = this->disassembleInstruction(address, b);

        if(instruction->hasTargets())
        {
            std::for_each(instruction->targets.begin(), instruction->targets.end(), [this](address_t target) {
                this->disassemble(target);
            });
        }

        if(this->_assembler->done(instruction))
            break;

        address += instruction->size;
        segment = this->_format->segment(address);
    }

    this->_assembler->popState();
    return true;
}

InstructionPtr Disassembler::disassembleInstruction(address_t address, Buffer& b)
{
    InstructionPtr instruction = std::make_shared<Instruction>();
    instruction->address = address;

    REDasm::status("Disassembling " + REDasm::hex(address));

    if(this->_assembler->decode(b, instruction))
    {
        if(this->_emulator)
            this->_emulator->emulate(instruction);

        const OperandList& operands = instruction->operands;

        std::for_each(operands.begin(), operands.end(), [this, instruction](const Operand& operand) {
            this->_assembler->analyzeOperand(this, instruction, operand);
        });
    }
    else
        this->createInvalidInstruction(instruction, b);

    this->_listing.commit(address, instruction);
    return instruction;
}

void Disassembler::createInvalidInstruction(const InstructionPtr &instruction, Buffer& b)
{
    instruction->type = InstructionTypes::Invalid;
    instruction->mnemonic = INVALID_MNEMONIC;

    if(instruction->bytes.empty())
    {
        std::stringstream ss;
        ss << std::hex << *b;
        instruction->bytes = ss.str();
    }

    REDasm::log("Invalid instruction @ " + REDasm::hex(instruction->address) +
                (!instruction->bytes.empty() ? " (bytes: " + instruction->bytes + ")" : ""));
}

}
