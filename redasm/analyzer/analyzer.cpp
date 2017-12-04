#include "analyzer.h"

namespace REDasm {

Analyzer::Analyzer(DisassemblerFunctions *dfunctions): _dfunctions(dfunctions)
{

}

Analyzer::~Analyzer()
{

}

void Analyzer::analyze(Listing &listing)
{
    listing.symbolTable()->iterate(SymbolTypes::FunctionMask, [this, &listing](SymbolPtr symbol) -> bool {
        this->findTrampolines(listing, symbol);
        return true;
    });
}

void Analyzer::findTrampolines(Listing &listing, SymbolPtr symbol)
{
    if(symbol->is(SymbolTypes::Locked))
        return;

    SymbolTable* symboltable = listing.symbolTable();
    Listing::iterator it = listing.find(symbol->address);

    if(it == listing.end())
        return;

    const ProcessorPlugin* processor = listing.processor();
    ReferenceTable* references = listing.referenceTable();
    SymbolPtr symimport;

    if(PROCESSOR_IS(processor, "x86"))
        symimport = this->findTrampolines_x86(it, symboltable);
    else if(PROCESSOR_IS(processor, "ARM"))
        symimport = this->findTrampolines_arm(it, symboltable);

    if(!symimport || !symimport->is(SymbolTypes::Import))
        return;

    symbol->type |= SymbolTypes::Locked;
    symboltable->update(symbol, "_" + REDasm::normalize(symimport->name));
    references->push(symimport, it.key);
}

SymbolPtr Analyzer::findTrampolines_x86(Listing::iterator& it, SymbolTable* symboltable)
{
    const InstructionPtr& instruction = *it;

    if(!instruction->is(InstructionTypes::Jump))
        return NULL;

    if(!instruction->hasTargets())
        return NULL;

    return symboltable->symbol(instruction->target());
}

SymbolPtr Analyzer::findTrampolines_arm(Listing::iterator& it, SymbolTable *symboltable)
{
    const InstructionPtr& instruction1 = *it;
    const InstructionPtr& instruction2 = *(++it);

    if((instruction1->mnemonic != "ldr") && (instruction2->mnemonic != "ldr"))
        return NULL;

    if(!instruction1->operands[1].is(OperandTypes::Memory) && (instruction2->operands[0].reg.r != ARM_REG_PC))
        return NULL;

    u64 target = instruction1->operands[1].u_value, importaddress = 0;

    if(!this->_dfunctions->readAddress(target, sizeof(u32), importaddress))
        return NULL;

    SymbolPtr symbol = symboltable->symbol(target), impsymbol = symboltable->symbol(importaddress);

    if(symbol)
        symboltable->update(symbol, "imp." + impsymbol->name);

    return impsymbol;
}

void Analyzer::createFunction(SymbolTable *symboltable, const std::string &name, address_t address)
{
    if(symboltable->erase(address)) // Analyzer can replace unlocked symbols
    {
        symboltable->createFunction(address, name);
        symboltable->symbol(address)->lock();
    }

    this->_dfunctions->disassemble(address);
}

void Analyzer::createFunction(SymbolTable *symboltable, address_t address)
{
    if(symboltable->erase(address)) // Analyzer can replace unlocked symbols
    {
        symboltable->createFunction(address);
        symboltable->symbol(address)->lock();
    }

    this->_dfunctions->disassemble(address);
}

} // namespace REDasm
