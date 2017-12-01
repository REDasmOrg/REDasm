#ifndef PSXEXE_ANALYZER_H
#define PSXEXE_ANALYZER_H

#include <unordered_map>
#include "../../analyzer/analyzer.h"
#include "../../analyzer/signatures.h"

namespace REDasm {

class PsxExeAnalyzer: public Analyzer
{
    public:
        PsxExeAnalyzer(DisassemblerFunctions* dfunctions);
        virtual void analyze(Listing &listing);

    private:
        bool analyzeFunction(Listing &listing, const Signatures &psyq, const SymbolPtr& symbol);
        void detectMain(Listing& listing);

    private:
        Signatures _psyq46;
};

}

#endif // PSXEXE_ANALYZER_H
