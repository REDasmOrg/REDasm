#include "elf_analyzer.h"

namespace REDasm {

ElfAnalyzer::ElfAnalyzer(DisassemblerAPI *disassembler, const SignatureFiles &signatures): Analyzer(disassembler, signatures)
{

}

void ElfAnalyzer::analyze()
{
    Analyzer::analyze();
    SymbolPtr symbol = m_document->symbol("main");

    if(symbol)
        m_document->setDocumentEntry(symbol->address);
}

} // namespace REDasm
