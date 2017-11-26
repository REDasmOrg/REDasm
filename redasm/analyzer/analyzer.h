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
        typedef std::function<bool(address_t, size_t, u64&)> ReadAddressProc;

    public:
        Analyzer();
        virtual ~Analyzer();
        virtual void analyze(Listing& listing);
        void initCallbacks(const DisassembleInstructionProc& disassembleinstruction, const DisassembleProc& disassemble, const ReadAddressProc& readaddress);

    private:
        void findTrampolines(Listing& listing, Symbol *symbol);
        Symbol* findTrampolines_x86(Listing::iterator& it, SymbolTable *symboltable, const ProcessorPlugin *processor);
        Symbol* findTrampolines_arm(Listing::iterator& it, SymbolTable *symboltable);

    protected:
        void createFunction(SymbolTable* symboltable, const std::string& name, address_t address);
        void createFunction(SymbolTable* symboltable, address_t address);
        bool readAddress(address_t address, size_t size, u64& value);
        void disassemble(address_t address);
        InstructionPtr disassembleInstruction(address_t address);

    private:
        ReadAddressProc _readaddress;
        DisassembleInstructionProc _disassembleinstruction;
        DisassembleProc _disassemble;
};

}

#endif // ANALYZER_H
