#include "elf_analyzer.h"

#define LIBC_START_MAIN   "__libc_start_main"
#define LIBC_START_MAIN_C 7

namespace REDasm {

ElfAnalyzer::ElfAnalyzer(DisassemblerAPI *disassembler, const SignatureFiles &signatures): Analyzer(disassembler, signatures) { }

void ElfAnalyzer::analyze()
{
    Analyzer::analyze();
    SymbolPtr symbol = m_document->symbol("main");

    if(!symbol)
    {
        AssemblerPlugin* assembler = m_disassembler->assembler();
        SymbolPtr symlibcmain = m_document->symbol(LIBC_START_MAIN);

        if(symlibcmain)
        {
            if(ASSEMBLER_IS(assembler, "x86"))
                this->findMain_x86(symlibcmain);
            else
                REDasm::log("WARNING: Unhandled architecture " + REDasm::quoted(assembler->name()));

            symbol = m_document->symbol("main");
        }
    }

    if(symbol)
        m_document->setDocumentEntry(symbol->address);
    else
        REDasm::log("WARNING: Cannot find 'main' symbol");
}

void ElfAnalyzer::findMain_x86(const SymbolPtr& symlibcmain)
{
    ReferenceVector refs = m_disassembler->getReferences(symlibcmain->address);

    if(refs.size() > 1)
        REDasm::log(REDasm::quoted(LIBC_START_MAIN) + " contains " + std::to_string(refs.size()) + " reference(s)");

    auto it = m_document->instructionItem(refs.front());

    if(it == m_document->end())
        return;

    it--; // Skip call
    InstructionPtr instruction = m_document->instruction((*it)->address);

    if(instruction->is(InstructionTypes::Load))
        this->findMain_x86_reg(it);
    else if(instruction->is(InstructionTypes::Push))
        this->findMain_x86_stack(it);
}

void ElfAnalyzer::findMain_x86_stack(ListingDocument::iterator it)
{
}

void ElfAnalyzer::findMain_x86_reg(ListingDocument::iterator it)
{

}

} // namespace REDasm
