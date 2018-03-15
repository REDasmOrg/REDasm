#include "listing.h"
#include "../../support/serializer.h"
#include "../../plugins/format.h"

namespace REDasm {

Listing::Listing(): cache_map<address_t, InstructionPtr>("instructions"), _assembler(NULL), _referencetable(NULL), _symboltable(NULL)
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

AssemblerPlugin *Listing::assembler() const
{
    return this->_assembler;
}

void Listing::setFormat(FormatPlugin *format)
{
    this->_format = format;
}

void Listing::setAssembler(AssemblerPlugin *assembler)
{
    this->_assembler = assembler;
}

void Listing::setSymbolTable(SymbolTable *symboltable)
{
    this->_symboltable = symboltable;
}

void Listing::setReferenceTable(ReferenceTable *referencetable)
{
    this->_referencetable = referencetable;
}

void Listing::checkBounds(address_t address)
{
    if(!this->_assembler)
        return;

    auto it = this->_paths.find(address);

    if(it != this->_paths.end())
        this->_paths.erase(it);

    FunctionPath path;
    this->walk(address, path);

    if(path.empty())
        return;

    this->updateBlockInfo(path);
    this->_paths[address] = path;
}

void Listing::updateBlockInfo(Listing::FunctionPath &path)
{
    auto it = path.begin();
    InstructionPtr lastinstruction;
    SymbolPtr lastsymbol;

    while(it != path.end())
    {
        InstructionPtr instruction = (*this)[*it];
        SymbolPtr symbol = this->_symboltable->symbol(instruction->address);

        if(instruction->is(InstructionTypes::Stop))
            instruction->blocktype |= BlockTypes::GraphEnd | (IS_LABEL(symbol) ? BlockTypes::Ignore : BlockTypes::BlockEnd);
        else if(IS_LABEL(symbol))
        {
            if(lastinstruction)
            {
                lastinstruction->blocktype |= BlockTypes::GraphEnd | (IS_LABEL(lastsymbol) ? BlockTypes::Ignore : BlockTypes::BlockEnd);
                this->update(lastinstruction);
            }

            instruction->blocktype |= BlockTypes::BlockStart | BlockTypes::GraphStart;
        }
        else if(lastinstruction && lastinstruction->is(InstructionTypes::Jump))
        {
            lastinstruction->blocktype |= BlockTypes::GraphEnd;
            instruction->blocktype |= BlockTypes::GraphStart;
            this->update(lastinstruction);
        }

        this->update(instruction);
        lastinstruction = instruction;
        lastsymbol = symbol;
        it++;
    }

    InstructionPtr firstinstruction = (*this)[*path.begin()];
    lastinstruction = (*this)[*path.rbegin()];

    firstinstruction->blocktype = BlockTypes::BlockStart | BlockTypes::GraphStart;
    this->update(firstinstruction);

    if(firstinstruction == lastinstruction)
        return;

    lastinstruction->blocktype = BlockTypes::BlockEnd | BlockTypes::GraphEnd;
    this->update(lastinstruction);
}

std::string Listing::getSignature(const SymbolPtr& symbol)
{
    std::string sig;
    auto it = this->_paths.find(symbol->address);

    if(it == this->_paths.end())
        return std::string();

    const FunctionPath& path = it->second;

    std::for_each(path.begin(), path.end(), [this, &sig](address_t address) {
        InstructionPtr instruction = (*this)[address];
        sig += instruction->bytes;
    });

    return sig;
}

SymbolPtr Listing::getFunction(address_t address)
{
    FunctionPaths::iterator it = this->findFunction(address);

    if(it == this->_paths.end())
        return NULL;

    return this->_symboltable->symbol(it->first);
}

bool Listing::getFunctionBounds(address_t address, address_t *startaddress, address_t *endaddress)
{
    FunctionPaths::iterator it = this->findFunction(address);

    if(it == this->_paths.end())
        return false;

    if(startaddress)
        *startaddress = *it->second.begin();

    if(endaddress)
    {
        InstructionPtr instruction = (*this)[*it->second.rbegin()];
        *endaddress = instruction->endAddress();
    }

    return true;
}

bool Listing::iterateFunction(address_t address, Listing::InstructionCallback cbinstruction)
{
    return this->iterateFunction(address, cbinstruction, NULL, NULL, NULL);
}

bool Listing::iterateFunction(address_t address, Listing::InstructionCallback cbinstruction, Listing::SymbolCallback cbstart, Listing::InstructionCallback cbend, Listing::SymbolCallback cblabel)
{
    if(!this->_assembler)
        return false;

    auto it = this->findFunction(address);

    if(it == this->_paths.end())
        return false;

    SymbolPtr symbol = NULL, functionsymbol = this->_symboltable->symbol(it->first);

    if(cbstart && functionsymbol)
        cbstart(functionsymbol);

    const FunctionPath& path = it->second;
    InstructionPtr instruction;

    std::for_each(path.begin(), path.end(), [this, &symbol, &instruction, &cbinstruction, &cblabel](address_t address) {
        symbol = this->_symboltable->symbol(address);

        if(cblabel && IS_LABEL(symbol))
            cblabel(symbol);

        instruction = (*this)[address];
        cbinstruction(instruction);
    });

    if(cbend && instruction)
        cbend(instruction);

    return true;
}

void Listing::iterateAll(InstructionCallback cbinstruction, SymbolCallback cbstart, InstructionCallback cbend, SymbolCallback cblabel)
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

void Listing::splitFunctionAt(const InstructionPtr &instruction)
{
    if(!this->stopFunctionAt(instruction))
        return;

    auto iit = this->find(instruction->endAddress());

    if(iit == this->end())
        return;

    this->_symboltable->createFunction(instruction->endAddress()); // Create new function here
    this->checkBounds(instruction->endAddress());
}

bool Listing::stopFunctionAt(const InstructionPtr &instruction)
{
    auto it = this->findFunction(instruction->address);

    if(it == this->_paths.end())
    {
        REDasm::log("Cannot stop function @ " + REDasm::hex(instruction->address));
        return false;
    }

    instruction->type |= InstructionTypes::Stop;
    this->update(instruction);
    this->checkBounds(it->first);
    return true;
}

void Listing::markEntryPoint()
{
    SymbolPtr symbol = this->_symboltable->entryPoint();

    if(!symbol)
        return;

    auto it = this->find(symbol->address);

    if(it == this->end())
        return;

    InstructionPtr instruction = *it;
    instruction->cmt("Entry Point");
    this->update(instruction);
}

void Listing::serialize(const InstructionPtr &value, std::fstream &fs)
{
    Serializer::serializeScalar(fs, value->address);
    Serializer::serializeScalar(fs, value->target_idx);
    Serializer::serializeScalar(fs, value->type);
    Serializer::serializeScalar(fs, value->size);
    Serializer::serializeScalar(fs, value->blocktype);
    Serializer::serializeScalar(fs, value->id);

    Serializer::serializeString(fs, value->mnemonic);
    Serializer::serializeString(fs, value->bytes);

    Serializer::serializeArray<std::list, address_t>(fs, value->targets, [this, &fs](address_t target) {
        Serializer::serializeScalar(fs, target);
    });

    Serializer::serializeArray<std::set, address_t>(fs, value->references, [this, &fs](address_t ref) {
        Serializer::serializeScalar(fs, ref);
    });

    Serializer::serializeArray<std::vector, Operand>(fs, value->operands, [this, &fs](const Operand& op) {
        Serializer::serializeScalar(fs, op.loc_index);
        Serializer::serializeScalar(fs, op.type);
        Serializer::serializeScalar(fs, op.extra_type);
        Serializer::serializeScalar(fs, op.size);
        Serializer::serializeScalar(fs, op.index);

        Serializer::serializeScalar(fs, op.reg.extra_type);
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
    Serializer::deserializeScalar(fs, &value->target_idx);
    Serializer::deserializeScalar(fs, &value->type);
    Serializer::deserializeScalar(fs, &value->size);
    Serializer::deserializeScalar(fs, &value->blocktype);
    Serializer::deserializeScalar(fs, &value->id);

    Serializer::deserializeString(fs, value->mnemonic);
    Serializer::deserializeString(fs, value->bytes);

    Serializer::deserializeArray<std::list, address_t>(fs, value->targets, [this, &fs](address_t& target) {
        Serializer::deserializeScalar(fs, &target);
    });

    Serializer::deserializeArray<std::set, address_t>(fs, value->references, [this, &fs](address_t& ref) {
        Serializer::deserializeScalar(fs, &ref);
    });

    Serializer::deserializeArray<std::vector, Operand>(fs, value->operands, [this, &fs](Operand& op) {
        Serializer::deserializeScalar(fs, &op.loc_index);
        Serializer::deserializeScalar(fs, &op.type);
        Serializer::deserializeScalar(fs, &op.extra_type);
        Serializer::deserializeScalar(fs, &op.size);
        Serializer::deserializeScalar(fs, &op.index);

        Serializer::deserializeScalar(fs, &op.reg.extra_type);
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

void Listing::walk(address_t startaddress, Listing::FunctionPath &path)
{
    std::stack<address_t> pending;
    pending.push(startaddress);

    this->_assembler->pushState();

    while(!pending.empty())
    {
        address_t address = pending.top();
        pending.pop();

        Segment* segment = this->_format->segment(address);

        if(!segment || !segment->is(SegmentTypes::Code))
            continue;

        Listing::iterator it = this->find(address);

        while(it != this->end())
        {
            if(path.find(it.key) != path.end())
                break;

            InstructionPtr instruction = *it;
            path.insert(it.key);

            if(instruction->is(InstructionTypes::Jump))
            {
                std::for_each(instruction->targets.begin(),instruction->targets.end(), [this, &pending](address_t target) {
                    if(!this->isFunctionStart(target))
                        pending.push(target);
                });
            }

            if(this->_assembler->done(instruction))
                break;

            it++;

            if((it == this->end()) || this->isFunctionStart((*it)->address))
                break;
        }
    }

    this->_assembler->popState();
}

bool Listing::isFunctionStart(address_t address)
{
    SymbolPtr symbol = this->_symboltable->symbol(address);

    if(!symbol)
        return false;

    return symbol->isFunction();
}

Listing::FunctionPaths::iterator Listing::findFunction(address_t address)
{
    auto it = this->_paths.find(address);

    if(it != this->_paths.end())
        return it;

    for(it = this->_paths.begin(); it != this->_paths.end(); it++)
    {
        const FunctionPath& path = it->second;
        address_t startaddress = *path.begin(), endaddress = *path.rbegin();

        if((endaddress < address) || (startaddress > address))
            continue;

        auto pathit = path.find(address);

        if(pathit != path.end())
            return it;
    }

    return this->_paths.end();
}

}
