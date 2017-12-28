#include "disassembler.h"
#include <algorithm>
#include <memory>

#define INVALID_MNEMONIC "db"
#define BRANCH_DIRECTION(instruction, destination) (static_cast<s64>(destination) - static_cast<s64>(instruction->address))

namespace REDasm {

Disassembler::Disassembler(Buffer buffer, ProcessorPlugin *processor, FormatPlugin *format): DisassemblerBase(buffer, format), _processor(processor)
{
    this->_printer = PrinterPtr(this->_processor->createPrinter(this, this->_symboltable));
    this->_emulator = processor->hasVMIL() ? processor->createEmulator(this) : NULL;

    this->_listing.setFormat(this->_format);
    this->_listing.setProcessor(this->_processor);
    this->_listing.setSymbolTable(this->_symboltable);
    this->_listing.setReferenceTable(&this->_referencetable);
}

Disassembler::~Disassembler()
{
    if(this->_emulator)
        delete this->_emulator;

    delete this->_processor;
}

ProcessorPlugin *Disassembler::processor()
{
    return this->_processor;
}

Listing& Disassembler::listing()
{
    return this->_listing;
}

bool Disassembler::canBeJumpTable(address_t address)
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
    std::unique_ptr<VMIL::Emulator> emulator(this->_processor->createEmulator(this));

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

void Disassembler::checkRegister(const InstructionPtr &instruction, const Operand &operand)
{
    if(!this->_emulator || !instruction->is(InstructionTypes::Branch) || !operand.is(OperandTypes::Register) || (operand.index != instruction->target_idx))
        return;

    address_t target = 0;

    if(!this->_emulator->read(operand, target))
        return;

    if(!this->_processor->canEmulateVMIL())
    {
        instruction->cmt(REDasm::hex(target));
        REDasm::log("VMIL @ " + REDasm::hex(instruction->address) + " jump to " + REDasm::hex(target));
        return;
    }

    if(!this->disassemble(target))
        return;

    SymbolPtr symbol = this->_symboltable->symbol(target);

    instruction->target(target);
    instruction->cmt(symbol->name);
    this->_listing.update(instruction);
    this->_referencetable.push(symbol, instruction->address);
}

void Disassembler::analyzeOp(const InstructionPtr &instruction, const Operand &operand)
{
    if(operand.is(OperandTypes::Register))
    {
        this->checkRegister(instruction, operand);
        return;
    }

    u64 value = operand.is(OperandTypes::Displacement) ? operand.mem.displacement : operand.u_value, opvalue = value;
    SymbolPtr symbol = this->_symboltable->symbol(value);

    if(!symbol || (symbol && !symbol->is(SymbolTypes::Import))) // Don't try to dereference imports
    {
        if(operand.is(OperandTypes::Memory) && (operand.isRead() || instruction->is(InstructionTypes::Branch)))
        {
            if(this->dereferencePointer(value, opvalue)) // Try to read pointed memory
                this->_symboltable->createLocation(value, SymbolTypes::Data | SymbolTypes::Pointer); // Create Symbol for pointer
        }
    }

    const Segment* segment = this->_format->segment(opvalue);

    if(!segment)
        return;

    if(instruction->is(InstructionTypes::Call))
    {
        if(instruction->hasTargets())
        {
            if(operand.index == instruction->target_idx)
            {
                if(symbol && !symbol->isFunction()) // This symbol will be promoted to function
                    this->_symboltable->erase(opvalue);

                if(this->_symboltable->createFunction(opvalue)) // This operand is the target
                    this->disassemble(opvalue);
            }
        }
    }
    else
    {
        bool wide = false;

        if(instruction->is(InstructionTypes::Jump))
        {
            if(!operand.is(OperandTypes::Displacement) || operand.mem.displacementOnly())
            {
                int dir = BRANCH_DIRECTION(instruction, opvalue);

                if(dir < 0)
                    instruction->cmt("Possible loop");
                else if(!dir)
                    instruction->cmt("Infinite loop");

                this->_listing.update(instruction);
                this->_symboltable->createLocation(opvalue, SymbolTypes::Code);
            }
            else
                this->checkJumpTable(instruction, operand);
        }
        else if(!segment->is(SegmentTypes::Bss) && (this->locationIsString(opvalue, &wide) >= MIN_STRING))
        {
            if(wide)
            {
                this->_symboltable->createWString(opvalue);
                instruction->cmt("UNICODE: " + this->readWString(opvalue));
            }
            else
            {
                this->_symboltable->createString(opvalue);
                instruction->cmt("STRING: " + this->readString(opvalue));
            }

            this->_listing.update(instruction);
        }
        else
            this->_symboltable->createLocation(opvalue, SymbolTypes::Data);
    }

    symbol = this->_symboltable->symbol(opvalue);

    if(symbol)
        this->_referencetable.push(symbol, instruction->address);
}

bool Disassembler::disassemble(address_t address)
{
    const Segment* segment = this->_format->segment(address);

    if(!segment || !segment->is(SegmentTypes::Code))
        return false;

    this->_processor->pushState();

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

        if(this->_processor->done(instruction))
            break;

        address += instruction->size;
        segment = this->_format->segment(address);
    }

    this->_processor->popState();
    return true;
}

InstructionPtr Disassembler::disassembleInstruction(address_t address, Buffer& b)
{
    InstructionPtr instruction = std::make_shared<Instruction>();
    instruction->address = address;

    REDasm::status("Disassembling " + REDasm::hex(address));

    if(!this->_processor->decode(b, instruction))
    {
        instruction->type = InstructionTypes::Invalid;
        instruction->mnemonic = INVALID_MNEMONIC;
        instruction->size = 1;
        instruction->imm(static_cast<u64>(*b));

        REDasm::log("Invalid instruction at " + REDasm::hex(address));
    }
    else
    {
        if(this->_processor->canEmulateVMIL() && this->_emulator)
            this->_emulator->emulate(instruction);

        const OperandList& operands = instruction->operands;

        std::for_each(operands.begin(), operands.end(), [this, instruction](const Operand& operand) {
            this->analyzeOp(instruction, operand);
        });
    }

    this->_listing.commit(address, instruction);
    return instruction;
}

}
