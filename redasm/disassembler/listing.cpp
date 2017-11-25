#include "listing.h"

namespace REDasm {

Listing::Listing(): std::map<address_t, InstructionPtr>(), _processor(NULL), _referencetable(NULL), _symboltable(NULL)
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

address_t Listing::getStop(const Symbol *symbol)
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
        const InstructionPtr& instruction = it->second;
        address = instruction->address;

        if(instruction->is(InstructionTypes::Stop))
            break;

        if(instruction->is(InstructionTypes::Jump) && this->_processor->target(instruction, &target))
        {
            if(this->find(target) != this->end())
                maxtarget = std::max(target, maxtarget);
        }

        it++;

        if(this->isFunctionStart(it->second->address)) // Don't overlap functions
            return address;
    }

    if(maxtarget > address)
        return this->getStop(maxtarget);

    return address;
}

std::string Listing::getSignature(Symbol* symbol)
{
    std::string sig;
    auto it = this->find(symbol->address);
    address_t endaddress = this->getStop(symbol);

    for(; it != this->end(); it++)
    {
        const InstructionPtr& instruction = it->second;

        if(instruction->address > endaddress)
            break;

        sig += instruction->signature;
    }

    return sig;
}

void Listing::iterate(const Symbol* symbol, InstructionCallback f)
{
    if(!this->_processor)
        return;

    address_t endaddress = this->getStop(symbol->address);
    auto it = this->find(symbol->address);

    for(; it != this->end(); it++)
    {
        const InstructionPtr& instruction = it->second;

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

    Symbol* currentsymbol = NULL;
    address_t target = 0, endaddress = 0;

    std::for_each(this->begin(), this->end(), [this, cbinstruction, cbstart, cbend, cblabel, &currentsymbol, &target, &endaddress](const Listing::Item& item) {
        Symbol* symbol = this->_symboltable->symbol(item.first);

        if(symbol && symbol->isFunction())
        {
            currentsymbol = symbol;
            endaddress = this->getStop(symbol);
            cbstart(currentsymbol);
        }
        else if(symbol && symbol->is(SymbolTypes::Code))
            cblabel(symbol);

        cbinstruction(item.second);

        if((item.first == endaddress) && currentsymbol)
        {
            cbend(currentsymbol);
            currentsymbol = NULL;
        }
    });
}

bool Listing::isFunctionStart(address_t address)
{
    Symbol* symbol = this->_symboltable->symbol(address);

    if(!symbol)
        return false;

    return symbol->isFunction();
}

}
