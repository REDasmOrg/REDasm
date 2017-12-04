#ifndef ANALYZER_H
#define ANALYZER_H

#include <functional>
#include <memory>
#include "../plugins/processor/processor.h"
#include "../disassembler/types/listing.h"
#include "../disassembler/types/symboltable.h"
#include "../disassembler/disassemblerfunctions.h"

namespace REDasm {

class Analyzer
{
    public:
        Analyzer(DisassemblerFunctions* dfunctions);
        virtual ~Analyzer();
        virtual void analyze(Listing& listing);

    private:
        void findTrampolines(Listing& listing, SymbolPtr symbol);
        SymbolPtr findTrampolines_x86(Listing::iterator& it, SymbolTable *symboltable);
        SymbolPtr findTrampolines_arm(Listing::iterator& it, SymbolTable *symboltable);

    protected:
        void createFunction(SymbolTable* symboltable, const std::string& name, address_t address);
        void createFunction(SymbolTable* symboltable, address_t address);

    protected:
        DisassemblerFunctions* _dfunctions;
};

}

#endif // ANALYZER_H
