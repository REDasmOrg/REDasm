#ifndef GBA_ANALYZER_H
#define GBA_ANALYZER_H

#include "../../analyzer/analyzer.h"

namespace REDasm {

class GbaAnalyzer : public Analyzer
{
    public:
        GbaAnalyzer(DisassemblerAPI* disassembler, const SignatureFiles& signaturefiles);
        virtual void analyze(Listing &listing);

    private:
        void renameEPBranch(Listing &listing, SymbolTable *symboltable);
};

} // namespace REDasm

#endif // GBA_ANALYZER_H
