#include "gba_analyzer.h"

namespace REDasm {

GbaAnalyzer::GbaAnalyzer(DisassemblerAPI* disassembler, const SignatureFiles& signaturefiles): Analyzer(disassembler, signaturefiles)
{

}

void GbaAnalyzer::analyze(Listing &listing)
{
    Analyzer::analyze(listing);

    SymbolTable* symboltable = listing.symbolTable();
    this->renameEPBranch(listing, symboltable);
}

void GbaAnalyzer::renameEPBranch(Listing& listing, SymbolTable* symboltable)
{
    SymbolPtr symbol = symboltable->entryPoint();

    if(!symbol)
        return;

    InstructionPtr instruction = listing[symbol->address];

    if(!instruction->hasTargets())
        return;

    symbol = symboltable->symbol(instruction->target());

    if(!symbol)
        return;

    symbol->lock();
    symboltable->update(symbol, "rom_ep");
}

} // namespace REDasm
