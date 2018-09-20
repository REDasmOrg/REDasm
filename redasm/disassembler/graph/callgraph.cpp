#include "callgraph.h"
#include <queue>

namespace REDasm {

CallGraph::CallGraph(ListingDocument *document): Graphing::Graph(), m_document(document)
{

}

void CallGraph::walk(address_t address)
{
    this->buildVertices(address);
    this->buildEdges();
    this->setRootVertex(this->vertexIdByAddress(address));
    this->layout();
}

void CallGraph::buildVertices(address_t fromaddress)
{
    std::queue<address_t> pending;
    pending.push(fromaddress);

    while(!pending.empty())
    {
        address_t address = pending.front();
        pending.pop();

        if(this->vertexIdByAddress(address))
            continue;

        auto it = m_document->instructionItem(address);

        if(it == m_document->end())
            continue;

        CallGraphVertex* cgv = new CallGraphVertex(m_document->symbol(address));
        this->pushVertex(cgv);

        m_byaddress[address] = cgv->id;

        while(it != m_document->end())
        {
            ListingItem* item = it->get();

            if(item->is(ListingItem::InstructionItem))
            {
                InstructionPtr instruction = m_document->instruction(item->address);

                if(instruction->is(InstructionTypes::Call))
                {
                    for(address_t target : instruction->targets)
                    {
                        cgv->calls.insert(target);
                        pending.push(target);
                    }
                }
            }
            else if(item->is(ListingItem::SymbolItem))
            {
                SymbolPtr symbol = m_document->symbol(item->address);

                if(!symbol->is(SymbolTypes::Code))
                    break;
            }
            else
                break;

            it++;
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
    auto it = m_byaddress.find(address);

    if(it == m_byaddress.end())
        return 0;

    return it->second;
}

} // namespace REDasm
