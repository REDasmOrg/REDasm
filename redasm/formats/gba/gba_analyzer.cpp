#include "gba_analyzer.h"

namespace REDasm {

GbaAnalyzer::GbaAnalyzer(DisassemblerAPI* disassembler, const SignatureFiles& signaturefiles): Analyzer(disassembler, signaturefiles)
{

}

void GbaAnalyzer::analyze()
{
    Analyzer::analyze();
    this->renameEPBranch();
}

void GbaAnalyzer::renameEPBranch()
{
    SymbolPtr symbol = m_document->documentEntry();

    if(!symbol)
        return;

    /*
    InstructionPtr instruction = document[symbol->address];

    if(!instruction->hasTargets())
        return;

    symbol = symboltable->symbol(instruction->target());

    if(!symbol)
        return;

    symbol->lock();
    symboltable->update(symbol, "rom_ep");
    */
}

} // namespace REDasm
