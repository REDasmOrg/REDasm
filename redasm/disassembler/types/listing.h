#ifndef LISTING_H
#define LISTING_H

#include <functional>
#include <map>
#include "../../plugins/processor/processor.h"
#include "../../redasm.h"
#include "referencetable.h"
#include "symboltable.h"

namespace REDasm {

class FormatPlugin;

class Listing: public std::map<address_t, InstructionPtr>
{
    public:
        typedef std::pair<address_t, InstructionPtr> Item;

    private:
        typedef std::function<void(const InstructionPtr&)> InstructionCallback;
        typedef std::function<void(const SymbolPtr&)> SymbolCallback;

    public:
        Listing();
        ReferenceTable* referenceTable() const;
        SymbolTable* symbolTable() const;
        FormatPlugin *format() const;
        const ProcessorPlugin *processor() const;
        void setFormat(FormatPlugin *format);
        void setProcessor(ProcessorPlugin *processor);
        void setSymbolTable(SymbolTable* symboltable);
        void setReferenceTable(ReferenceTable* referencetable);
        address_t getStop(const SymbolPtr &symbol);
        std::string getSignature(const SymbolPtr &symbol);
        void iterate(const SymbolPtr &symbol, InstructionCallback f);
        void iterateAll(InstructionCallback cbinstruction, SymbolCallback cbstart, SymbolCallback cbend, SymbolCallback cblabel);

    private:
        address_t getStop(address_t address);
        bool isFunctionStart(address_t address);

    private:
        FormatPlugin* _format;
        ProcessorPlugin* _processor;
        ReferenceTable* _referencetable;
        SymbolTable* _symboltable;
};

}

#endif // LISTING_H
