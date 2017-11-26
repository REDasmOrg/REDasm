#include "pe_analyzer.h"
#include "pe_utils.h"
#include "../../plugins/format.h"

#define IMPORT_NAME(library, name) PEUtils::importName(library, name)
#define IMPORT_TRAMPOLINE(library, name) ("_" + REDasm::normalize(IMPORT_NAME(library, name)))
#define ADD_WNDPROC_API(argidx, name) _wndprocapi.push_back(std::make_pair(argidx, name))

namespace REDasm {

PEAnalyzer::PEAnalyzer(DisassemblerFunctions *dfunctions): Analyzer(dfunctions)
{
    ADD_WNDPROC_API(4, "DialogBoxA");
    ADD_WNDPROC_API(4, "DialogBoxW");
    ADD_WNDPROC_API(4, "DialogBoxParamA");
    ADD_WNDPROC_API(4, "DialogBoxParamW");
    ADD_WNDPROC_API(4, "CreateDialogParamA");
    ADD_WNDPROC_API(4, "CreateDialogParamW");
}

void PEAnalyzer::analyze(Listing &listing)
{
    Analyzer::analyze(listing);
    this->findStopAPI(listing, "kernel32.dll", "ExitProcess");
    this->findStopAPI(listing, "kernel32.dll", "TerminateProcess");
    this->findAllWndProc(listing);
}

Symbol *PEAnalyzer::getImport(Listing &listing, const std::string &library, const std::string &api)
{
    SymbolTable* symboltable = listing.symbolTable();
    Symbol* symbol = symboltable->symbol(IMPORT_TRAMPOLINE(library, api));

    if(!symbol)
        symbol = symboltable->symbol(IMPORT_NAME(library, api));

    return symbol;
}

ReferenceVector PEAnalyzer::getAPIReferences(Listing& listing, const std::string &library, const std::string &api)
{
    ReferenceTable* referencetable = listing.referenceTable();
    Symbol* symbol = this->getImport(listing, library, api);

    if(!symbol)
        return ReferenceVector();

    auto it = referencetable->references(symbol);

    if(it == referencetable->end())
        return ReferenceVector();

    return referencetable->toVector(it->second);
}

void PEAnalyzer::findStopAPI(Listing &listing, const std::string& library, const std::string& api)
{
    ReferenceVector refs = this->getAPIReferences(listing, library, api);

    std::for_each(refs.begin(), refs.end(), [](const InstructionPtr& instruction) {
       instruction->type |= InstructionTypes::Stop;
    });
}

void PEAnalyzer::findAllWndProc(Listing &listing)
{
    for(auto it = this->_wndprocapi.begin(); it != this->_wndprocapi.end(); it++)
    {
        ReferenceVector refs = this->getAPIReferences(listing, "user32.dll", it->second);

        std::for_each(refs.begin(), refs.end(), [this, &listing, it](const InstructionPtr& instruction) {
            this->findWndProc(listing, instruction, it->first);
        });
    }
}

void PEAnalyzer::findWndProc(Listing &listing, const InstructionPtr& callinstruction, size_t argidx)
{
    auto it = listing.find(callinstruction->address);

    if(it == listing.end())
        return;

    size_t arg = 0;
    it--; // Skip call

    while(arg < argidx)
    {
        const InstructionPtr& instruction = it->second;

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
                    Symbol* symbol = symboltable->symbol(address);
                    std::string name = "DlgProc_" + REDasm::hex(address, 0, false);

                    if(symbol)
                    {
                        symbol->type = SymbolTypes::Function;
                        symboltable->rename(symbol, name);
                    }
                    else
                        symboltable->createFunction(address, name);

                    this->_dfunctions->disassemble(address);
                }
            }
        }

        if((arg == argidx) || (it == listing.begin()) || instruction->is(InstructionTypes::Stop))
            break;

        it--;
    }
}

}
