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
        virtual void analyze();

    private:
        void disassembleTrampoline(address_t eventva, const std::string &name);
        void decompileObject(const VBPublicObjectDescriptor& pubobjdescr);
        void decompile( SymbolPtr thunrtdata);

    private:
        const PeFormat* m_peformat;
        VBHeader* m_vbheader;
        VBProjectInfo* m_vbprojinfo;
        VBObjectTable* m_vbobjtable;
        VBObjectTreeInfo* m_vbobjtreeinfo;
        VBPublicObjectDescriptor* m_vbpubobjdescr;
};

} // namespace REDasm

#endif // VB_ANALYZER_H
