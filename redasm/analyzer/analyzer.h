#ifndef ANALYZER_H
#define ANALYZER_H

#include <functional>
#include <memory>
#include "../plugins/processor/processor.h"
#include "../disassembler/listing.h"
#include "../disassembler/symboltable.h"

namespace REDasm {

class Analyzer
{
    private:
        typedef std::function<InstructionPtr(address_t)> DisassembleInstructionProc;
        typedef std::function<void(address_t)> DisassembleProc;

    public:
        Analyzer();
        virtual ~Analyzer();
        virtual void analyze(Listing& listing);
        void initCallbacks(const DisassembleInstructionProc& disassembleinstruction, const DisassembleProc& disassemble);

    private:
        void findTrampolines(Listing& listing, Symbol *symbol);

    protected:
        void createFunction(SymbolTable* symboltable, const std::string& name, address_t address);
        void createFunction(SymbolTable* symboltable, address_t address);
        InstructionPtr disassembleInstruction(address_t address);
        void disassemble(address_t address);

    private:
        DisassembleInstructionProc _disassembleinstruction;
        DisassembleProc _disassemble;
};

}

#endif // ANALYZER_H
