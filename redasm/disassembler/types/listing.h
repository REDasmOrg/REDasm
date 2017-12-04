#ifndef LISTING_H
#define LISTING_H

#include <functional>
#include <map>
#include "../../plugins/processor/processor.h"
#include "../../support/cachemap.h"
#include "../../redasm.h"
#include "referencetable.h"
#include "symboltable.h"

namespace REDasm {

class FormatPlugin;

class Listing: public cache_map<address_t, InstructionPtr>
{
    private:
        typedef std::function<void(const InstructionPtr&)> InstructionCallback;
        typedef std::function<void(const SymbolPtr&)> SymbolCallback;
        typedef std::map<address_t, address_t> FunctionBounds;

    public:
        Listing();
        virtual ~Listing();
        ReferenceTable* referenceTable() const;
        SymbolTable* symbolTable() const;
        FormatPlugin *format() const;
        const ProcessorPlugin *processor() const;
        std::string getSignature(const SymbolPtr &symbol);
        bool getFunctionBounds(address_t address, address_t *start, address_t *end) const;
        void setFormat(FormatPlugin *format);
        void setProcessor(ProcessorPlugin *processor);
        void setSymbolTable(SymbolTable* symboltable);
        void setReferenceTable(ReferenceTable* referencetable);
        void iterate(const SymbolPtr &symbol, InstructionCallback f);
        bool iterateFunction(address_t address, InstructionCallback cbinstruction, SymbolCallback cbstart, SymbolCallback cbend, SymbolCallback cblabel);
        void iterateAll(InstructionCallback cbinstruction, SymbolCallback cbstart, SymbolCallback cbend, SymbolCallback cblabel);
        void update(const InstructionPtr& instruction);
        void calculateBounds();

    protected:
        virtual void serialize(const InstructionPtr &value, std::fstream &fs);
        virtual void deserialize(InstructionPtr &value, std::fstream &fs);

    private:
        address_t getStop(address_t address);
        bool isFunctionStart(address_t address);

    private:
        FunctionBounds _bounds;
        FormatPlugin* _format;
        ProcessorPlugin* _processor;
        ReferenceTable* _referencetable;
        SymbolTable* _symboltable;
};

}

#endif // LISTING_H
