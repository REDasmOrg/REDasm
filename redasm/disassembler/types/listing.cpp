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
            if((target > address) && (this->find(target) != this->end()))
            {
                SymbolPtr symbol = this->_symboltable->symbol(target);

                if(!symbol || !symbol->isFunction())
                    maxtarget = std::max(target, maxtarget);
            }
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

bool Listing::getFunctionBounds(address_t address, address_t *start, address_t *end) const
{
    for(auto it = this->_bounds.begin(); it != this->_bounds.end(); it++)
    {
        if((address >= it->first) && (address <= it->second))
        {
            if(start) *start = it->first;
            if(end) *end = it->second;
            return true;
        }
    }

    return false;
}

std::string Listing::getSignature(const SymbolPtr& symbol)
{
    std::string sig;
    address_t endaddress = 0;
    auto it = this->find(symbol->address);

    if(!this->getFunctionBounds(symbol->address, NULL, &endaddress))
        return std::string();

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
    if(!this->_processor )
        return;

    address_t endaddress = 0;

    if(!this->getFunctionBounds(symbol->address, NULL, &endaddress))
        return;

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

bool Listing::iterateFunction(address_t address, Listing::InstructionCallback cbinstruction, Listing::SymbolCallback cbstart, Listing::SymbolCallback cbend, Listing::SymbolCallback cblabel)
{
    if(!this->_processor)
        return false;

    address_t startaddress = 0, endaddress = 0;

    if(!this->getFunctionBounds(address, &startaddress, &endaddress))
        return false;

    auto it = this->find(startaddress);
    SymbolPtr symbol = NULL, functionsymbol = this->_symboltable->symbol(startaddress);

    if(functionsymbol)
        cbstart(functionsymbol);

    while(it != this->end())
    {
        symbol = this->_symboltable->symbol(it.key);

        if(symbol && !symbol->isFunction() && symbol->is(SymbolTypes::Code))
            cblabel(symbol);

        cbinstruction(*it);

        if(it.key == endaddress)
            break;

        it++;
    }

    if(functionsymbol)
        cbend(functionsymbol);

    return true;
}

void Listing::iterateAll(InstructionCallback cbinstruction, SymbolCallback cbstart, SymbolCallback cbend, SymbolCallback cblabel)
{
    this->_symboltable->iterate(SymbolTypes::FunctionMask, [this, cbinstruction, cbstart, cbend, cblabel](const SymbolPtr& symbol) -> bool {
        this->iterateFunction(symbol->address, cbinstruction, cbstart, cbend, cblabel);
        return true;
    });
}

void Listing::update(const InstructionPtr &instruction)
{
    this->commit(instruction->address, instruction);
}

void Listing::calculateBounds()
{
    this->_symboltable->iterate(SymbolTypes::FunctionMask, [this](SymbolPtr symbol) -> bool {
        this->_bounds[symbol->address] = this->getStop(symbol->address);
        return true;
    });
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
