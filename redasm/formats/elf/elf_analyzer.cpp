#include "elf_analyzer.h"

namespace REDasm {

ElfAnalyzer::ElfAnalyzer(DisassemblerAPI *disassembler, const SignatureFiles &signatures): Analyzer(disassembler, signatures)
{

}

void ElfAnalyzer::analyze(Listing &listing)
{
    Analyzer::analyze(listing);
    SymbolTable* symbolable = listing.symbolTable();
    SymbolPtr symbol = symbolable->symbol("main");

    if(symbol)
        symbolable->setEntryPoint(symbol);
}

} // namespace REDasm
