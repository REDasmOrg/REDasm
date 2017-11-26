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
        typedef std::pair<address_t, Symbol*> LabelItem;
        typedef std::map<address_t, Symbol*> LabelMap;

    private:
        typedef std::function<void(const InstructionPtr&)> InstructionCallback;
        typedef std::function<void(const Symbol*)> SymbolCallback;

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
        address_t getStop(const Symbol *symbol);
        std::string getSignature(Symbol *symbol);
        void iterate(const Symbol *symbol, InstructionCallback f);
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
