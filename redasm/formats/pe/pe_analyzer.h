#ifndef PE_ANALYZER_H
#define PE_ANALYZER_H

#include "../../analyzer/analyzer.h"

namespace REDasm {

class PEAnalyzer: public Analyzer
{
    private:
        typedef std::pair<size_t, std::string> APIInfo;

    public:
        PEAnalyzer(DisassemblerAPI* disassembler, const SignatureFiles &signatures);
        virtual void analyze(InstructionsPool& listing);

    private:
        SymbolPtr getImport(InstructionsPool& listing, const std::string& library, const std::string& api);
        ReferenceVector getAPIReferences(InstructionsPool &listing, const std::string& library, const std::string& api);
        void findStopAPI(InstructionsPool& listing, const std::string &library, const std::string &api);
        void findAllWndProc(InstructionsPool& listing);
        void findWndProc(InstructionsPool& listing, address_t address, size_t argidx);

    private:
        std::list<APIInfo> _wndprocapi;
};

}

#endif // PE_ANALYZER_H
