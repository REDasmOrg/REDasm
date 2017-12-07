#include "disassembler.h"
#include <algorithm>
#include <memory>

#define INVALID_MNEMONIC "db"
#define BRANCH_DIRECTION(instruction, destination) (static_cast<s64>(destination) - static_cast<s64>(instruction->address))

namespace REDasm {

Disassembler::Disassembler(Buffer buffer, ProcessorPlugin *processor, FormatPlugin *format): DisassemblerBase(buffer, format), _processor(processor)
{
    this->_printer = PrinterPtr(this->_processor->createPrinter(this, this->_symboltable));

    this->_listing.setFormat(this->_format);
    this->_listing.setProcessor(this->_processor);
    this->_listing.setSymbolTable(this->_symboltable);
    this->_listing.setReferenceTable(&this->_referencetable);
}

Disassembler::~Disassembler()
{
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

void Disassembler::disassembleFunction(address_t address)
{
    SymbolPtr symbol = this->_symboltable->symbol(address);

    if(!symbol || symbol->isFunction())
        return;

    this->_symboltable->erase(address);
    this->_symboltable->createFunction(address);
    this->disassemble(address);

    STATUS("Analyzing...");
    Analyzer analyzer(this, this->_format->signatures());
    analyzer.analyze(this->_listing); // Run basic analyzer

    STATUS("Calculating paths...");
    this->_listing.calculatePaths();
}

void Disassembler::disassemble()
{
    // Preload format functions for analysis
    this->_symboltable->iterate(SymbolTypes::FunctionMask, [this](SymbolPtr symbol) -> bool {
        this->disassemble(symbol->address);
        return true;
    });

    std::unique_ptr<Analyzer> a(this->_format->createAnalyzer(this, this->_format->signatures()));

    STATUS("Calculating paths...");
    this->_listing.calculatePaths();

    if(a)
    {
        STATUS("Analyzing...");
        a->analyze(this->_listing);

        STATUS("Recalculating paths...");
        this->_listing.calculatePaths();
    }

    STATUS("Sorting symbols...");
    this->_symboltable->sort();

    STATUS("Marking Entry Point...");
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

void Disassembler::checkJumpTable(const InstructionPtr &instruction, const Operand& op)
{
    bool isjumptable = false;
    size_t cases = 0;
    address_t address = op.mem.displacement, target = 0;

    this->_symboltable->createLocation(address, SymbolTypes::Data);
    SymbolPtr jmpsymbol = this->_symboltable->symbol(address);

    while(this->readAddress(address, op.mem.scale, target))
    {
        Segment* segment = this->_format->segment(target);

        if(!segment || !segment->is(SegmentTypes::Code))
            break;

        isjumptable = true;
        instruction->target(target);
        this->disassemble(target);

        if(this->_symboltable->createLocation(target, SymbolTypes::Code))
        {
            SymbolPtr symbol = this->_symboltable->symbol(target);
            auto it = this->_listing.find(target);

            if(it != this->_listing.end())
            {
                InstructionPtr tgtinstruction = *it;
                tgtinstruction->cmt("JUMP_TABLE @ " + REDasm::hex(instruction->address) + " case " + std::to_string(cases));
                this->_listing.update(tgtinstruction);
                this->_referencetable.push(jmpsymbol, tgtinstruction->address);
            }

            if(symbol)
                this->_referencetable.push(symbol, instruction->address);
        }

        address += op.mem.scale;
        cases++;
    }

    if(isjumptable)
    {
        instruction->type = InstructionTypes::JumpTable;
        this->_listing.update(instruction);
        instruction->cmt("#" + std::to_string(cases) + " case(s) jump table");
    }
}

void Disassembler::analyzeOp(const InstructionPtr &instruction, const Operand &operand)
{
    if(operand.is(OperandTypes::Register))
        return;

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

void Disassembler::disassemble(address_t address)
{
    const Segment* segment = this->_format->segment(address);
    this->_processor->pushState();

    while(segment && segment->is(SegmentTypes::Code)) // Don't disassemble data/junk
    {
        if(this->_listing.find(address) != this->_listing.end())
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
    else
    {
        const OperandList& operands = instruction->operands;

        std::for_each(operands.begin(), operands.end(), [this, instruction](const Operand& operand) {
            this->analyzeOp(instruction, operand);
        });
    }

    this->_listing.commit(address, instruction);
    return instruction;
}

}
