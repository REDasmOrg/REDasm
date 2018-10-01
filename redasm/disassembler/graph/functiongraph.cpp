#include "functiongraph.h"
#include "../../graph/graph_layout.h"

namespace REDasm {
namespace Graphing {

FunctionGraph::FunctionGraph(ListingDocument* document): Graph(), m_document(document) { }
ListingDocument* FunctionGraph::document() { return m_document; }

void FunctionGraph::build(address_t address)
{
    this->buildNodes(address);
    this->buildEdges();
    this->setRootVertex(this->vertexFromAddress(address));
    this->layout();
}

FunctionGraphVertex *FunctionGraph::vertexFromAddress(address_t address)
{
    for(auto& item : m_vertexmap)
    {
       FunctionGraphVertex* v = static_cast<FunctionGraphVertex*>(this->getVertex(item.first));

        if(v->contains(address))
            return v;
    }

    return NULL;
}

void FunctionGraph::buildNode(address_t address, FunctionGraph::AddressQueue &addressqueue)
{
    auto it = m_document->instructionItem(address);

    if(it == m_document->end())
        return;

    std::unique_ptr<FunctionGraphVertex> fgv = std::make_unique<FunctionGraphVertex>(address);
    ListingItem* item = it->get();

    for( ; it != m_document->end(); it++)
    {
        item = it->get();

        if(this->vertexFromAddress(item->address))
            break;

        if(item->is(ListingItem::SymbolItem))
        {
            SymbolPtr symbol = m_document->symbol(item->address);

            if(symbol->is(SymbolTypes::Code) && !symbol->isFunction())
                addressqueue.push(item->address);
        }

        if(!item->is(ListingItem::InstructionItem))
            break;

        fgv->end = item->address;
        InstructionPtr instruction = m_document->instruction(item->address);

        if(instruction->is(InstructionTypes::Jump))
        {
            for(address_t target : instruction->targets)
                addressqueue.push(target);

            if(instruction->is(InstructionTypes::Conditional))
                addressqueue.push(instruction->endAddress());

            break;
        }

        if(instruction->is(InstructionTypes::Stop))
            break;
    }

    if(!item)
        return;

    fgv->startidx = m_document->indexOfInstruction(fgv->start);
    fgv->endidx = m_document->indexOfInstruction(fgv->end);
    this->pushVertex(fgv.release());
}

void FunctionGraph::buildNodes(address_t startaddress)
{
    REDasm::ListingItem* item = m_document->functionStart(startaddress);
    startaddress = item->address;

    std::queue<address_t> queue;
    queue.push(startaddress);

    while(!queue.empty())
    {
        address_t address = queue.front();
        queue.pop();

        item = m_document->functionStart(address);

        if(!item || (item->address != startaddress) || this->vertexFromAddress(address))
            continue;

        this->buildNode(address, queue);
    }
}

void FunctionGraph::buildEdges()
{
    for(auto vit = this->begin(); vit != this->end(); vit++)
    {
        FunctionGraphVertex* v = static_cast<FunctionGraphVertex*>(*vit);
        auto it = m_document->instructionItem(v->start);

        while(it != m_document->end())
        {
            ListingItem* item = it->get();

            if(!v->contains(item->address))
                break;

            InstructionPtr instruction = m_document->instruction(item->address);

            if(instruction->is(InstructionTypes::Jump))
            {
                for(address_t target : instruction->targets)
                {
                    Graphing::Vertex* tov = this->vertexFromAddress(target);

                    if(!tov)
                        continue;

                    this->edge(v, tov);
                    v->bTrue(tov);
                }

                if(instruction->is(InstructionTypes::Conditional))
                {
                    Graphing::Vertex* tov = this->vertexFromAddress(instruction->endAddress());
                    this->edge(v, tov);
                    v->bFalse(tov);
                }
            }

            it++;
        }
    }
}

} // namespace Graphing
} // namespace REDasm
