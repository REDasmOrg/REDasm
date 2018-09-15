#include "psxexe_analyzer.h"
#include "../../plugins/format.h"

namespace REDasm {

PsxExeAnalyzer::PsxExeAnalyzer(DisassemblerAPI *disassembler, const SignatureFiles &signaturefiles): Analyzer(disassembler, signaturefiles)
{
}

void PsxExeAnalyzer::analyze()
{
    Analyzer::analyze();
    this->detectMain();
}

void PsxExeAnalyzer::detectMain()
{
    SymbolPtr symentry = m_document->documentEntry();

    if(!symentry)
        return;

    bool initheap = false;

    /*
    document.iterateFunction(symentry->address, [symboltable, &initheap](const InstructionPtr& instruction)-> bool {
        if(instruction->mnemonic != "jal")
            return true;

        SymbolPtr symbol = symboltable->symbol(instruction->operands[0].u_value);

        if(!symbol)
            return !initheap; // Continue until InitHeap is found

        if(initheap) {
            symbol->lock();
            symboltable->update(symbol, "main");
            symboltable->setEntryPoint(symbol);
            return false;
        }

        if(symbol->name == "InitHeap")
            initheap = true;

        return true;
    });
    */
}

}
