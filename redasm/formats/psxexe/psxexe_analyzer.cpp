#include "psxexe_analyzer.h"
#include "../../analyzer/signatures.h"
#include "../../plugins/format.h"

namespace REDasm {

PsxExeAnalyzer::PsxExeAnalyzer(DisassemblerFunctions *dfunctions): Analyzer(dfunctions)
{
    this->_psyq46.load("signatures/psyq46.json");
}

void PsxExeAnalyzer::analyze(Listing& listing)
{
    listing.symbolTable()->iterate(SymbolTypes::FunctionMask, [this, &listing](Symbol* symbol) -> bool {
        return this->analyzeFunction(listing, this->_psyq46, symbol);
    });

    this->detectMain(listing);
}

bool PsxExeAnalyzer::analyzeFunction(Listing& listing, const Signatures& psyq, Symbol *symbol)
{
    if(symbol->type & SymbolTypes::Locked)
        return true;

    SymbolTable* symboltable = listing.symbolTable();
    std::string fsig = listing.getSignature(symbol);
    const picojson::array arr = psyq.signatures();

    for(auto it = arr.begin(); it != arr.end(); it++)
    {
        const picojson::object& obj = it->get<picojson::object>();
        std::string psig = obj.at("signature").to_str();

        if(!psyq.match(fsig, psig))
            continue;

        symbol->type |= SymbolTypes::Import;
        symbol->lock();
        symboltable->rename(symbol, obj.at("name").to_str());
        break;
    }

    return true;
}

void PsxExeAnalyzer::detectMain(Listing &listing)
{
    SymbolTable* symboltable = listing.symbolTable();
    Symbol* symentry = symboltable->entryPoint();

    if(!symentry)
        return;

    bool initheap = false;

    listing.iterate(symentry, [symboltable, &initheap](const InstructionPtr& instruction)-> bool {
        if(instruction->mnemonic != "jal")
            return true;

        Symbol* symbol = symboltable->symbol(instruction->operands[0].u_value);

        if(!symbol)
            return !initheap; // Continue until InitHeap is found

        if(initheap) {
            symbol->lock();
            symboltable->rename(symbol, "main");
            return false;
        }

        if(symbol->name == "InitHeap")
            initheap = true;

        return true;
    });
}

}
