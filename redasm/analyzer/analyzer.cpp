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
    listing.symbolTable()->iterate(SymbolTypes::FunctionMask, [this, &listing](Symbol* symbol) -> bool {
        this->findTrampolines(listing, symbol);
        return true;
    });
}

void Analyzer::findTrampolines(Listing &listing, Symbol* symbol)
{
    if(symbol->is(SymbolTypes::Locked))
        return;

    SymbolTable* symboltable = listing.symbolTable();
    Listing::iterator it = listing.find(symbol->address);

    if(it == listing.end())
        return;

    const ProcessorPlugin* processor = listing.processor();
    Symbol* symimport = NULL;

    if(PROCESSOR_IS(processor, "x86"))
        symimport = this->findTrampolines_x86(it, symboltable, processor);
    else if(PROCESSOR_IS(processor, "ARM"))
        symimport = this->findTrampolines_arm(it, symboltable);

    if(!symimport || !symimport->is(SymbolTypes::Import))
        return;

    symbol->type |= SymbolTypes::Locked;
    symboltable->rename(symbol, "_" + REDasm::normalize(symimport->name));
}

Symbol* Analyzer::findTrampolines_x86(Listing::iterator& it, SymbolTable* symboltable, const ProcessorPlugin* processor)
{
    const InstructionPtr& instruction = it->second;

    if(!instruction->is(InstructionTypes::Jump))
        return NULL;

    address_t target = 0;

    if(!processor->target(instruction, &target))
        return NULL;

    return symboltable->symbol(target);
}

Symbol* Analyzer::findTrampolines_arm(Listing::iterator& it, SymbolTable *symboltable)
{
    const InstructionPtr& instruction1 = it->second;
    const InstructionPtr& instruction2 = (++it)->second;

    if((instruction1->mnemonic != "ldr") && (instruction2->mnemonic != "ldr"))
        return NULL;

    if(!instruction1->operands[1].is(OperandTypes::Memory) && (instruction2->operands[0].reg.r != ARM_REG_PC))
        return NULL;

    u64 target = instruction1->operands[1].u_value, importaddress = 0;

    if(!this->_dfunctions->readAddress(target, sizeof(u32), importaddress))
        return NULL;

    Symbol *symbol = symboltable->symbol(target), *impsymbol = symboltable->symbol(importaddress);

    if(symbol)
        symboltable->rename(symbol, "imp." + impsymbol->name);

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
