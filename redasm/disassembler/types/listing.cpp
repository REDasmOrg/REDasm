#include "listing.h"

namespace REDasm {

Listing::Listing(): cache_map<address_t, InstructionPtr>("instructions"), _processor(NULL), _referencetable(NULL), _symboltable(NULL)
{

}

Listing::~Listing()
{

}

ReferenceTable *Listing::referenceTable() const
{
    return this->_referencetable;
}

SymbolTable *Listing::symbolTable() const
{
    return this->_symboltable;
}

FormatPlugin *Listing::format() const
{
    return this->_format;
}

const ProcessorPlugin* Listing::processor() const
{
    return this->_processor;
}

void Listing::setFormat(FormatPlugin *format)
{
    this->_format = format;
}

address_t Listing::getStop(const SymbolPtr& symbol)
{
    return this->getStop(symbol->address);
}

void Listing::setProcessor(ProcessorPlugin *processor)
{
    this->_processor = processor;
}

void Listing::setSymbolTable(SymbolTable *symboltable)
{
    this->_symboltable = symboltable;
}

void Listing::setReferenceTable(ReferenceTable *referencetable)
{
    this->_referencetable = referencetable;
}

address_t Listing::getStop(address_t address)
{
    if(!this->_processor)
        return address;

    address_t maxtarget = 0, target = 0;
    auto it = this->find(address);

    while(it != this->end())
    {
        const InstructionPtr& instruction = *it;
        address = instruction->address;

        if(instruction->is(InstructionTypes::Stop))
            break;

        if(instruction->is(InstructionTypes::Jump) && this->_processor->target(instruction, &target))
        {
            if(this->find(target) != this->end())
                maxtarget = std::max(target, maxtarget);
        }

        it++;

        if((it == this->end()))
            break;

        if(this->isFunctionStart((*it)->address)) // Don't overlap functions
            return address;
    }

    if(maxtarget > address)
        return this->getStop(maxtarget);

    return address;
}

std::string Listing::getSignature(const SymbolPtr& symbol)
{
    std::string sig;
    auto it = this->find(symbol->address);
    address_t endaddress = this->getStop(symbol);

    for(; it != this->end(); it++)
    {
        InstructionPtr instruction = *it;

        if(instruction->address > endaddress)
            break;

        sig += instruction->signature;
    }

    return sig;
}

void Listing::iterate(const SymbolPtr& symbol, InstructionCallback f)
{
    if(!this->_processor)
        return;

    address_t endaddress = this->getStop(symbol->address);
    auto it = this->find(symbol->address);

    for(; it != this->end(); it++)
    {
        InstructionPtr instruction = *it;

        if(instruction->address > endaddress)
            break;

        if(f)
            f(instruction);
    }
}

void Listing::iterateAll(InstructionCallback cbinstruction, SymbolCallback cbstart, SymbolCallback cbend, SymbolCallback cblabel)
{
    if(!this->_processor)
        return;

    SymbolPtr currentsymbol;
    address_t target = 0, endaddress = 0;

    std::for_each(this->begin(), this->end(), [this, cbinstruction, cbstart, cbend, cblabel, &currentsymbol, &target, &endaddress](const InstructionPtr& instruction) {
        SymbolPtr symbol = this->_symboltable->symbol(instruction->address);

        if(symbol && symbol->isFunction())
        {
            currentsymbol = symbol;
            endaddress = this->getStop(symbol);
            cbstart(currentsymbol);
        }
        else if(symbol && symbol->is(SymbolTypes::Code))
            cblabel(symbol);

        cbinstruction(instruction);

        if((instruction->address == endaddress) && currentsymbol)
        {
            cbend(currentsymbol);
            currentsymbol = NULL;
        }
    });
}

void Listing::update(const InstructionPtr &instruction)
{
    this->commit(instruction->address, instruction);
}

void Listing::serialize(const InstructionPtr &value, std::fstream &fs)
{
    Serializer::serializeScalar(fs, value->address);
    Serializer::serializeScalar(fs, value->type);
    Serializer::serializeScalar(fs, value->size);
    Serializer::serializeScalar(fs, value->id);

    Serializer::serializeString(fs, value->mnemonic);
    Serializer::serializeString(fs, value->signature);

    Serializer::serializeArray<std::vector, Operand>(fs, value->operands, [this, &fs](const Operand& op) {
        Serializer::serializeScalar(fs, op.loc_index);
        Serializer::serializeScalar(fs, op.type);
        Serializer::serializeScalar(fs, op.index);

        Serializer::serializeScalar(fs, op.reg.type);
        Serializer::serializeScalar(fs, op.reg.r);

        Serializer::serializeScalar(fs, op.mem.base);
        Serializer::serializeScalar(fs, op.mem.index);
        Serializer::serializeScalar(fs, op.mem.scale);
        Serializer::serializeScalar(fs, op.mem.displacement);

        Serializer::serializeScalar(fs, op.u_value);
    });

    Serializer::serializeArray<std::list, std::string>(fs, value->comments, [this, &fs](const std::string& s) {
        Serializer::serializeString(fs, s);
    });
}

void Listing::deserialize(InstructionPtr &value, std::fstream &fs)
{
    value = std::make_shared<Instruction>();

    Serializer::deserializeScalar(fs, &value->address);
    Serializer::deserializeScalar(fs, &value->type);
    Serializer::deserializeScalar(fs, &value->size);
    Serializer::deserializeScalar(fs, &value->id);

    Serializer::deserializeString(fs, value->mnemonic);
    Serializer::deserializeString(fs, value->signature);

    Serializer::deserializeArray<std::vector, Operand>(fs, value->operands, [this, &fs](Operand& op) {
        Serializer::deserializeScalar(fs, &op.loc_index);
        Serializer::deserializeScalar(fs, &op.type);
        Serializer::deserializeScalar(fs, &op.index);

        Serializer::deserializeScalar(fs, &op.reg.type);
        Serializer::deserializeScalar(fs, &op.reg.r);

        Serializer::deserializeScalar(fs, &op.mem.base);
        Serializer::deserializeScalar(fs, &op.mem.index);
        Serializer::deserializeScalar(fs, &op.mem.scale);
        Serializer::deserializeScalar(fs, &op.mem.displacement);

        Serializer::deserializeScalar(fs, &op.u_value);
    });

    Serializer::deserializeArray<std::list, std::string>(fs, value->comments, [this, &fs](std::string& s) {
        Serializer::deserializeString(fs, s);
    });
}

bool Listing::isFunctionStart(address_t address)
{
    SymbolPtr symbol = this->_symboltable->symbol(address);

    if(!symbol)
        return false;

    return symbol->isFunction();
}

}
