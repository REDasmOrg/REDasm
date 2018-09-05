#include "elf_analyzer.h"

namespace REDasm {

ElfAnalyzer::ElfAnalyzer(DisassemblerAPI *disassembler, const SignatureFiles &signatures): Analyzer(disassembler, signatures)
{

}

void ElfAnalyzer::analyze()
{
    Analyzer::analyze();
    SymbolTable* symbolable = m_disassembler->document()->symbols();
    SymbolPtr symbol = symbolable->symbol("main");

    if(symbol)
        symbolable->setEntryPoint(symbol);
}

} // namespace REDasm
