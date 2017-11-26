#ifndef PE_ANALYZER_H
#define PE_ANALYZER_H

#include "../../analyzer/analyzer.h"

namespace REDasm {

class PEAnalyzer: public Analyzer
{
    private:
        typedef std::pair<size_t, std::string> APIInfo;

    public:
        PEAnalyzer(DisassemblerFunctions* dfunctions);
        virtual void analyze(Listing& listing);

    private:
        Symbol* getImport(Listing& listing, const std::string& library, const std::string& api);
        ReferenceVector getAPIReferences(Listing &listing, const std::string& library, const std::string& api);
        void findStopAPI(Listing& listing, const std::string &library, const std::string &api);
        void findAllWndProc(Listing& listing);
        void findWndProc(Listing& listing, const InstructionPtr &callinstruction, size_t argidx);

    private:
        std::list<APIInfo> _wndprocapi;
};

}

#endif // PE_ANALYZER_H
