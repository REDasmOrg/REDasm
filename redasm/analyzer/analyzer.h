#ifndef ANALYZER_H
#define ANALYZER_H

#include <functional>
#include <memory>
#include "../plugins/processor/processor.h"
#include "../disassembler/types/listing.h"
#include "../disassembler/types/symboltable.h"
#include "../disassembler/disassemblerfunctions.h"
#include "../signatures/signaturedb.h"

namespace REDasm {

class Analyzer
{
    public:
        Analyzer(DisassemblerFunctions* dfunctions, const SignatureFiles& signaturefiles);
        virtual ~Analyzer();
        virtual void analyze(Listing& listing);

    private:
        bool checkCrc16(const SymbolPtr &symbol, const Signature &signature);
        void loadSignatures(Listing &listing);
        void findSignatures(const SignatureDB& signaturedb, Listing& listing);
        void findTrampolines(Listing& listing, SymbolPtr symbol);
        SymbolPtr findTrampolines_x86(Listing::iterator& it, SymbolTable *symboltable);
        SymbolPtr findTrampolines_arm(Listing::iterator& it, SymbolTable *symboltable);

    protected:
        void createFunction(SymbolTable* symboltable, const std::string& name, address_t address);
        void createFunction(SymbolTable* symboltable, address_t address);

    protected:
        DisassemblerFunctions* _dfunctions;
        const SignatureFiles& _signaturefiles;
};

}

#endif // ANALYZER_H
