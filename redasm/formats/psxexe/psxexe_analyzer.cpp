#include "psxexe_analyzer.h"
#include "../../plugins/format.h"

namespace REDasm {

PsxExeAnalyzer::PsxExeAnalyzer(DisassemblerFunctions *dfunctions, const SignatureFiles &signaturefiles): Analyzer(dfunctions, signaturefiles)
{
}

void PsxExeAnalyzer::analyze(Listing& listing)
{
    Analyzer::analyze(listing);
    this->detectMain(listing);
}

void PsxExeAnalyzer::detectMain(Listing &listing)
{
    SymbolTable* symboltable = listing.symbolTable();
    SymbolPtr symentry = symboltable->entryPoint();

    if(!symentry)
        return;

    bool initheap = false;

    listing.iterateFunction(symentry->address, [symboltable, &initheap](const InstructionPtr& instruction)-> bool {
        if(instruction->mnemonic != "jal")
            return true;

        SymbolPtr symbol = symboltable->symbol(instruction->operands[0].u_value);

        if(!symbol)
            return !initheap; // Continue until InitHeap is found

        if(initheap) {
            symbol->lock();
            symboltable->update(symbol, "main");
            return false;
        }

        if(symbol->name == "InitHeap")
            initheap = true;

        return true;
    });
}

}
