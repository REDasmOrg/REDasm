#ifndef ELF_ANALYZER_H
#define ELF_ANALYZER_H

#include "../../analyzer/analyzer.h"

namespace REDasm {

class ElfAnalyzer: public Analyzer
{
    public:
        ElfAnalyzer(DisassemblerFunctions* dfunctions, const SignatureFiles &signatures);
        virtual void analyze(Listing& listing);
};

} // namespace REDasm

#endif // ELF_ANALYZER_H
