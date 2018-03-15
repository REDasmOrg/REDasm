#include "callgraph.h"
#include <queue>

namespace REDasm {

CallGraph::CallGraph(Listing &listing): Graphing::Graph(), _listing(listing)
{

}

void CallGraph::walk(address_t address)
{
    this->buildVertices(address);
    this->buildEdges();

    SymbolPtr symbol = this->_listing.getFunction(address);

    if(!symbol)
        return;

    this->setRootVertex(this->vertexIdByAddress(symbol->address));
    this->layout();
}

void CallGraph::buildVertices(address_t fromaddress)
{
    std::queue<address_t> pending;
    pending.push(fromaddress);

    SymbolTable* symboltable = this->_listing.symbolTable();

    while(!pending.empty())
    {
        address_t address = pending.front(), startaddress = 0, endaddress = 0;
        pending.pop();

        if(this->vertexIdByAddress(address) || !this->_listing.getFunctionBounds(address, &startaddress, &endaddress))
            continue;

        SymbolPtr symbol = symboltable->symbol(startaddress);

        if(!symbol)
            continue;

        auto it = this->_listing.find(startaddress);

        if(it == this->_listing.end())
            continue;

        CallGraphVertex* cgv = new CallGraphVertex(symbol);
        this->pushVertex(cgv);

        this->_byaddress[symbol->address] = cgv->id;

        for( ; it != this->_listing.end(); it++)
        {
            InstructionPtr instruction = *it;

            if(instruction->address >= endaddress)
                break;

            if(!instruction->is(InstructionTypes::Call) || !instruction->hasTargets())
                continue;

            instruction->foreachTarget([this, cgv, &pending](address_t target) {
                cgv->calls.insert(target);
                pending.push(target);
            });
        }
    }
}

void CallGraph::buildEdges()
{
    for(Graphing::Vertex* v : *this)
    {
        CallGraphVertex* cgv = static_cast<CallGraphVertex*>(v);

        std::for_each(cgv->calls.begin(), cgv->calls.end(), [this, cgv](address_t call) {
            this->edge(cgv->id, this->vertexIdByAddress(call));
        });
    }
}

Graphing::vertex_id_t CallGraph::vertexIdByAddress(address_t address) const
{
    auto it = this->_byaddress.find(address);

    if(it == this->_byaddress.end())
        return 0;

    return it->second;
}

} // namespace REDasm
