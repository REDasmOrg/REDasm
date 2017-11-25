#include "analyzer.h"

namespace REDasm {

Analyzer::Analyzer()
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

void Analyzer::initCallbacks(const DisassembleInstructionProc &disassembleinstruction, const Analyzer::DisassembleProc &disassemble)
{
    this->_disassembleinstruction = disassembleinstruction;
    this->_disassemble = disassemble;
}

void Analyzer::findTrampolines(Listing &listing, Symbol* symbol)
{
    if(symbol->is(SymbolTypes::Locked))
        return;

    SymbolTable* symboltable = listing.symbolTable();
    auto it = listing.find(symbol->address);

    if(it == listing.end())
        return;

    const InstructionPtr& instruction = it->second;

    if(!instruction->is(InstructionTypes::Jump))
        return;

    const ProcessorPlugin* processor = listing.processor();
    address_t target = 0;

    if(!processor->target(instruction, &target))
        return;

    Symbol* symimport = symboltable->symbol(target);

    if(!symimport || !symimport->is(SymbolTypes::Import))
        return;

    symboltable->rename(symbol, "_" + REDasm::normalize(symimport->name));
}

void Analyzer::createFunction(SymbolTable *symboltable, const std::string &name, address_t address)
{
    if(symboltable->erase(address)) // Analyzer can replace unlocked symbols
    {
        symboltable->createFunction(address, name);
        symboltable->symbol(address)->lock();
    }

    this->disassemble(address);
}

void Analyzer::createFunction(SymbolTable *symboltable, address_t address)
{
    if(symboltable->erase(address)) // Analyzer can replace unlocked symbols
    {
        symboltable->createFunction(address);
        symboltable->symbol(address)->lock();
    }

    this->disassemble(address);
}

InstructionPtr Analyzer::disassembleInstruction(address_t address)
{
    if(!this->_disassembleinstruction)
        return NULL;

    return this->_disassembleinstruction(address);
}

void Analyzer::disassemble(address_t address)
{
    if(!this->_disassemble)
        return;

    this->_disassemble(address);
}

} // namespace REDasm
