#include "callgraph.h"
#include <queue>

namespace REDasm {

CallGraph::CallGraph(ListingDocument *document): Graphing::Graph(), m_document(document)
{

}

void CallGraph::walk(address_t address)
{
    /*
    this->buildVertices(address);
    this->buildEdges();

    SymbolPtr symbol = this->m_document.getFunction(address);

    if(!symbol)
        return;

    this->setRootVertex(this->vertexIdByAddress(symbol->address));
    this->layout();
    */
}

void CallGraph::buildVertices(address_t fromaddress)
{
    /*
    std::queue<address_t> pending;
    pending.push(fromaddress);

    SymbolTable* symboltable = this->m_document.symbolTable();

    while(!pending.empty())
    {
        address_t address = pending.front(), startaddress = 0, endaddress = 0;
        pending.pop();

        if(this->vertexIdByAddress(address) || !this->m_document.getFunctionBounds(address, &startaddress, &endaddress))
            continue;

        SymbolPtr symbol = symboltable->symbol(startaddress);

        if(!symbol)
            continue;

        auto it = this->m_document.find(startaddress);

        if(it == this->m_document.end())
            continue;

        CallGraphVertex* cgv = new CallGraphVertex(symbol);
        this->pushVertex(cgv);

        this->_byaddress[symbol->address] = cgv->id;

        for( ; it != this->m_document.end(); it++)
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
    */
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
    auto it = m_byaddress.find(address);

    if(it == m_byaddress.end())
        return 0;

    return it->second;
}

} // namespace REDasm
