#ifndef ELF_ANALYZER_H
#define ELF_ANALYZER_H

#include "../../analyzer/analyzer.h"

namespace REDasm {

class ElfAnalyzer: public Analyzer
{
    public:
        ElfAnalyzer(DisassemblerAPI* disassembler, const SignatureFiles &signatures);
        virtual void analyze();

    private:
        void findMain_x86(const SymbolPtr &symlibcmain);
        void findMain_x86_stack(ListingDocument::iterator it);
        void findMain_x86_reg(ListingDocument::iterator it);
};

} // namespace REDasm

#endif // ELF_ANALYZER_H
