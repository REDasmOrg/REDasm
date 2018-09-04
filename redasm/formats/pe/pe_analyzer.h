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
        virtual void analyze(ListingDocument* document);

    private:
        SymbolPtr getImport(ListingDocument* document, const std::string& library, const std::string& api);
        ReferenceVector getAPIReferences(ListingDocument* document, const std::string& library, const std::string& api);
        void findStopAPI(ListingDocument* document, const std::string &library, const std::string &api);
        void findAllWndProc(ListingDocument* document);
        void findWndProc(ListingDocument* document, address_t address, size_t argidx);

    private:
        std::list<APIInfo> m_wndprocapi;
};

}

#endif // PE_ANALYZER_H
