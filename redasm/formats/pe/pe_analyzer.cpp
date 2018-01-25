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

void PEAnalyzer::analyze(Listing &listing)
{
    Analyzer::analyze(listing);
    this->findStopAPI(listing, "kernel32.dll", "ExitProcess");
    this->findStopAPI(listing, "kernel32.dll", "TerminateProcess");
    this->findAllWndProc(listing);
}

SymbolPtr PEAnalyzer::getImport(Listing &listing, const std::string &library, const std::string &api)
{
    SymbolTable* symboltable = listing.symbolTable();
    SymbolPtr symbol = symboltable->symbol(IMPORT_TRAMPOLINE(library, api));

    if(!symbol)
        symbol = symboltable->symbol(IMPORT_NAME(library, api));

    return symbol;
}

ReferenceVector PEAnalyzer::getAPIReferences(Listing& listing, const std::string &library, const std::string &api)
{
    SymbolPtr symbol = this->getImport(listing, library, api);

    if(!symbol)
        return ReferenceVector();

    return this->_disassembler->getReferences(symbol);
}

void PEAnalyzer::findStopAPI(Listing &listing, const std::string& library, const std::string& api)
{
    ReferenceVector refs = this->getAPIReferences(listing, library, api);

    std::for_each(refs.begin(), refs.end(), [&listing](address_t address) {
        InstructionPtr instruction = listing[address];
        listing.splitFunctionAt(instruction);
    });
}

void PEAnalyzer::findAllWndProc(Listing &listing)
{
    for(auto it = this->_wndprocapi.begin(); it != this->_wndprocapi.end(); it++)
    {
        ReferenceVector refs = this->getAPIReferences(listing, "user32.dll", it->second);

        std::for_each(refs.begin(), refs.end(), [this, &listing, it](address_t address) {
            this->findWndProc(listing, address, it->first);
        });
    }
}

void PEAnalyzer::findWndProc(Listing &listing, address_t address, size_t argidx)
{
    auto it = listing.find(address);

    if(it == listing.end())
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
                FormatPlugin* format = listing.format();
                address_t address = instruction->operands[0].u_value;
                Segment* segment = format->segment(address);

                if(segment && segment->is(SegmentTypes::Code))
                {
                    SymbolTable* symboltable = listing.symbolTable();
                    SymbolPtr symbol = symboltable->symbol(address);
                    std::string name = "DlgProc_" + REDasm::hex(address, 0, false);

                    if(symbol)
                    {
                        symbol->type = SymbolTypes::Function;
                        symboltable->update(symbol, name);
                    }
                    else
                        symboltable->createFunction(address, name);
                }
            }
        }

        if((arg == argidx) || (it == listing.begin()) || instruction->is(InstructionTypes::Stop))
            break;

        it--;
    }
}

}
