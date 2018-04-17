#ifndef PSXEXE_ANALYZER_H
#define PSXEXE_ANALYZER_H

#include "../../analyzer/analyzer.h"

namespace REDasm {

class PsxExeAnalyzer: public Analyzer
{
    public:
        PsxExeAnalyzer(DisassemblerAPI* disassembler, const SignatureFiles& signaturefiles);
        virtual void analyze(Listing &listing);

    private:
        void detectMain(Listing& listing);
};

}

#endif // PSXEXE_ANALYZER_H
