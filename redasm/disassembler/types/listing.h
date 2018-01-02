#ifndef LISTING_H
#define LISTING_H

#include <functional>
#include <map>
#include "../../plugins/assembler/assembler.h"
#include "../../support/cachemap.h"
#include "../../redasm.h"
#include "referencetable.h"
#include "symboltable.h"

namespace REDasm {

class FormatPlugin;

class Listing: public cache_map<address_t, InstructionPtr>
{
    public:
        typedef std::function<void(const InstructionPtr&)> InstructionCallback;
        typedef std::function<void(const SymbolPtr&)> SymbolCallback;
        typedef std::set<address_t> FunctionPath;
        typedef std::map<address_t, FunctionPath> FunctionPaths;

    public:
        Listing();
        virtual ~Listing();
        ReferenceTable* referenceTable() const;
        SymbolTable* symbolTable() const;
        FormatPlugin *format() const;
        AssemblerPlugin *assembler() const;
        std::string getSignature(const SymbolPtr &symbol);
        SymbolPtr getFunction(address_t address);
        void setFormat(FormatPlugin *format);
        void setAssembler(AssemblerPlugin *assembler);
        void setSymbolTable(SymbolTable* symboltable);
        void setReferenceTable(ReferenceTable* referencetable);
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
        static void walk(Listing *listing, Listing::iterator it, FunctionPath &path);
        void updateBlockInfo(FunctionPath& path);
        bool isFunctionStart(address_t address);
        FunctionPaths::iterator findFunction(address_t address);

    private:
        FunctionPaths _paths;
        FormatPlugin* _format;
        AssemblerPlugin* _assembler;
        ReferenceTable* _referencetable;
        SymbolTable* _symboltable;

    friend class GraphBuilder;
};

}

#endif // LISTING_H
