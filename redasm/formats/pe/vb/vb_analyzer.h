#ifndef VB_ANALYZER_H
#define VB_ANALYZER_H

#include "../pe_analyzer.h"
#include "vb_header.h"

namespace REDasm {

class PeFormat;

class VBAnalyzer : public PEAnalyzer
{
    public:
        VBAnalyzer(DisassemblerAPI* disassembler, const SignatureFiles& signatures);
        virtual void analyze(Listing &listing);

    private:
        void disassembleTrampoline(u32 eventva, const std::string &name, Listing &listing);
        void decompileObject(Listing &listing, const VBPublicObjectDescriptor& pubobjdescr);
        void decompile(Listing &listing, SymbolPtr thunrtdata);

    private:
        const PeFormat* _peformat;
        VBHeader* _vbheader;
        VBProjectInfo* _vbprojinfo;
        VBObjectTable* _vbobjtable;
        VBObjectTreeInfo* _vbobjtreeinfo;
        VBPublicObjectDescriptor* _vbpubobjdescr;
};

} // namespace REDasm

#endif // VB_ANALYZER_H
