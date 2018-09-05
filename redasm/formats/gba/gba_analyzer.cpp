#include "gba_analyzer.h"

namespace REDasm {

GbaAnalyzer::GbaAnalyzer(DisassemblerAPI* disassembler, const SignatureFiles& signaturefiles): Analyzer(disassembler, signaturefiles)
{

}

void GbaAnalyzer::analyze()
{
    Analyzer::analyze();
    this->renameEPBranch(m_disassembler->document()->symbols());
}

void GbaAnalyzer::renameEPBranch(SymbolTable *symboltable)
{
    SymbolPtr symbol = symboltable->entryPoint();

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
