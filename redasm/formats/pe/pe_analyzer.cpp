#include "pe_analyzer.h"
#include "pe_utils.h"

#define IMPORT_NAME(library, name) PEUtils::importName(library, name)
#define IMPORT_TRAMPOLINE(library, name) ("_" + IMPORT_NAME(library, name))
#define ADD_WNDPROC_API(argidx, name) m_wndprocapi.push_back(std::make_pair(argidx, name))

namespace REDasm {

PEAnalyzer::PEAnalyzer(DisassemblerAPI *disassembler, const SignatureFiles& signatures): Analyzer(disassembler, signatures)
{
    ADD_WNDPROC_API(4, "DialogBoxA");
    ADD_WNDPROC_API(4, "DialogBoxW");
    ADD_WNDPROC_API(4, "DialogBoxParamA");
    ADD_WNDPROC_API(4, "DialogBoxParamW");
    ADD_WNDPROC_API(4, "CreateDialogParamA");
    ADD_WNDPROC_API(4, "CreateDialogParamW");
    ADD_WNDPROC_API(4, "CreateDialogIndirectParamA");
    ADD_WNDPROC_API(4, "CreateDialogIndirectParamW");
}

void PEAnalyzer::analyze()
{
    Analyzer::analyze();
    this->findAllWndProc();
}

SymbolPtr PEAnalyzer::getImport(const std::string &library, const std::string &api)
{
    SymbolPtr symbol = m_disassembler->document()->symbol(IMPORT_TRAMPOLINE(library, api));

    if(!symbol)
        symbol = m_disassembler->document()->symbol(IMPORT_NAME(library, api));

    return symbol;
}

ReferenceVector PEAnalyzer::getAPIReferences(const std::string &library, const std::string &api)
{
    SymbolPtr symbol = this->getImport(library, api);

    if(!symbol)
        return ReferenceVector();

    return m_disassembler->getReferences(symbol->address);
}

void PEAnalyzer::findAllWndProc()
{
    for(auto it = m_wndprocapi.begin(); it != m_wndprocapi.end(); it++)
    {
        ReferenceVector refs = this->getAPIReferences("user32.dll", it->second);

        for(address_t ref : refs)
            this->findWndProc(ref, it->first);
    }
}

void PEAnalyzer::findWndProc(address_t address, size_t argidx)
{
    auto it = m_document->instructionItem(address);

    if(it == m_document->end())
        return;

    size_t arg = 0;
    it--; // Skip call

    while(arg < argidx)
    {
        const InstructionPtr& instruction = m_document->instruction((*it)->address);

        if(instruction->is(InstructionTypes::Push))
        {
            arg++;

            if(arg == argidx)
            {
                Operand& op = instruction->op(0);
                Segment* segment = m_document->segment(op.u_value);

                if(segment && segment->is(SegmentTypes::Code))
                {
                    m_document->function(op.u_value, "DlgProc_" + REDasm::hex(op.u_value));
                    m_disassembler->disassemble(op.u_value);
                }
            }
        }

        if((arg == argidx) || (it == m_document->begin()) || instruction->is(InstructionTypes::Stop))
            break;

        it--;
    }
}

}
