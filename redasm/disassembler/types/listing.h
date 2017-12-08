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
        typedef std::set<address_t> FunctionPath;
        typedef std::map<address_t, FunctionPath> FunctionPaths;

    public:
        struct GraphPath { std::list<address_t> block;
                           std::list< std::shared_ptr<GraphPath> > paths; };

        typedef std::shared_ptr<GraphPath> GraphPathPtr;

    public:
        Listing();
        virtual ~Listing();
        ReferenceTable* referenceTable() const;
        SymbolTable* symbolTable() const;
        FormatPlugin *format() const;
        const ProcessorPlugin *processor() const;
        std::string getSignature(const SymbolPtr &symbol);
        void setFormat(FormatPlugin *format);
        void setProcessor(ProcessorPlugin *processor);
        void setSymbolTable(SymbolTable* symboltable);
        void setReferenceTable(ReferenceTable* referencetable);
        GraphPathPtr buildGraph(address_t address);
        bool iterateFunction(address_t address, InstructionCallback cbinstruction);
        bool iterateFunction(address_t address, InstructionCallback cbinstruction, SymbolCallback cbstart, InstructionCallback cbend, SymbolCallback cblabel);
        void iterateAll(InstructionCallback cbinstruction, SymbolCallback cbstart, InstructionCallback cbend, SymbolCallback cblabel);
        void update(const InstructionPtr& instruction);
        void calculatePaths();
        void markEntryPoint();

    protected:
        virtual void serialize(const InstructionPtr &value, std::fstream &fs);
        virtual void deserialize(InstructionPtr &value, std::fstream &fs);

    private:
        void walk(address_t address);
        void walk(Listing::iterator it, FunctionPath &path);
        void updateBlockInfo(FunctionPath& path);
        void buildGraph(const GraphPathPtr& graph, const FunctionPath& path, FunctionPath::iterator from);
        bool isFunctionStart(address_t address);
        FunctionPaths::iterator findFunction(address_t address);

    private:
        FunctionPaths _paths;
        FormatPlugin* _format;
        ProcessorPlugin* _processor;
        ReferenceTable* _referencetable;
        SymbolTable* _symboltable;
};

}

#endif // LISTING_H
