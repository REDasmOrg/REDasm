#include "pe_analyzer.h"
#include "pe_utils.h"
#include "../../plugins/format.h"

#define IMPORT_NAME(library, name) PEUtils::importName(library, name)
#define IMPORT_TRAMPOLINE(library, name) ("_" + REDasm::normalize(IMPORT_NAME(library, name)))
#define ADD_WNDPROC_API(argidx, name) _wndprocapi.push_back(std::make_pair(argidx, name))

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

void PEAnalyzer::analyze(ListingDocument *document)
{
    Analyzer::analyze(document);
    this->findStopAPI(document, "kernel32.dll", "ExitProcess");
    this->findStopAPI(document, "kernel32.dll", "TerminateProcess");
    this->findAllWndProc(document);
}

SymbolPtr PEAnalyzer::getImport(ListingDocument *document, const std::string &library, const std::string &api)
{
    SymbolTable* symboltable = document->symbols();
    SymbolPtr symbol = symboltable->symbol(IMPORT_TRAMPOLINE(library, api));

    if(!symbol)
        symbol = symboltable->symbol(IMPORT_NAME(library, api));

    return symbol;
}

ReferenceVector PEAnalyzer::getAPIReferences(ListingDocument *document, const std::string &library, const std::string &api)
{
    SymbolPtr symbol = this->getImport(document, library, api);

    if(!symbol)
        return ReferenceVector();

    return m_disassembler->getReferences(symbol);
}

void PEAnalyzer::findStopAPI(ListingDocument *document, const std::string& library, const std::string& api)
{
    /*
    ReferenceVector refs = this->getAPIReferences(document, library, api);

    std::for_each(refs.begin(), refs.end(), [&document](address_t address) {
        InstructionPtr instruction = document[address];
        document.splitFunctionAt(instruction);
    });
    */
}

void PEAnalyzer::findAllWndProc(ListingDocument *document)
{
    for(auto it = this->m_wndprocapi.begin(); it != this->m_wndprocapi.end(); it++)
    {
        //ReferenceVector refs = this->getAPIReferences(listing, "user32.dll", it->second);

        //std::for_each(refs.begin(), refs.end(), [this, &listing, it](address_t address) {
            //kthis->findWndProc(listing, address, it->first);
        //});
    }
}

void PEAnalyzer::findWndProc(ListingDocument *document, address_t address, size_t argidx)
{
    /*
    auto it = document.find(address);

    if(it == document.end())
        return;

    size_t arg = 0;
    it--; // Skip call

    while(arg < argidx)
    {
        const InstructionPtr& instruction = *it;

        if(instruction->is(InstructionTypes::Push))
        {
            arg++;

            if(arg == argidx)
            {
                FormatPlugin* format = document.format();
                Operand& op = instruction->op(0);
                Segment* segment = format->segment(op.u_value);

                if(segment && segment->is(SegmentTypes::Code))
                {
                    SymbolTable* symboltable = document.symbolTable();
                    symboltable->createFunction(op.u_value, "DlgProc_" + REDasm::hex(op.u_value, 0, false));
                    symboltable->lock(op.u_value);
                }
            }
        }

        if((arg == argidx) || (it == document.begin()) || instruction->is(InstructionTypes::Stop))
            break;

        it--;
    }
    */
}

}
