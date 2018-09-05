#ifndef ANALYZER_H
#define ANALYZER_H

#include <functional>
#include <memory>
#include "../plugins/assembler/assembler.h"
#include "../disassembler/listing/listingdocument.h"
#include "../disassembler/types/symboltable.h"
#include "../disassembler/disassemblerapi.h"
#include "../signatures/signaturedb.h"

namespace REDasm {

class Analyzer
{
    public:
        Analyzer(DisassemblerAPI* disassembler, const SignatureFiles& signaturefiles);
        virtual ~Analyzer();
        virtual void analyze();

    private:
        bool checkCrc16(const SymbolPtr &symbol, const Signature &signature, const SignatureDB &signaturedb);
        void loadSignatures();
        void findSignatures(SignatureDB &signaturedb, ListingDocument* document);
        void findTrampolines(SymbolPtr symbol);
        SymbolPtr findTrampolines_x86(ListingDocument::iterator it, SymbolTable *symboltable);
        SymbolPtr findTrampolines_arm(ListingDocument::iterator it, SymbolTable *symboltable);

    protected:
        DisassemblerAPI* m_disassembler;
        const SignatureFiles& m_signaturefiles;
};

}

#endif // ANALYZER_H
