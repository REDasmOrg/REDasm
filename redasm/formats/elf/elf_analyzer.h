#ifndef ELF_ANALYZER_H
#define ELF_ANALYZER_H

#include "../../analyzer/analyzer.h"

namespace REDasm {

class ElfAnalyzer: public Analyzer
{
    public:
        ElfAnalyzer(DisassemblerAPI* disassembler, const SignatureFiles &signatures);
        virtual void analyze(ListingDocument* document);
};

} // namespace REDasm

#endif // ELF_ANALYZER_H
