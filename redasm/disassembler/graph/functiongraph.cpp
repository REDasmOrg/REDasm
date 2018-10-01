#include "functiongraph.h"
#include "../../graph/graph_layout.h"

namespace REDasm {
namespace Graphing {

FunctionGraph::FunctionGraph(ListingDocument* document): Graph(), m_document(document) { }
ListingDocument* FunctionGraph::document() { return m_document; }

void FunctionGraph::build(address_t address)
{
    s64 idx = this->buildNodes(address);

    if(idx == -1)
        return;

    this->buildEdges();
    this->setRootVertex(this->vertexFromListingIndex(idx));
    this->layout();
}

FunctionGraphVertex *FunctionGraph::vertexFromListingIndex(s64 index)
{
    for(auto& item : m_vertexmap)
    {
       FunctionGraphVertex* v = static_cast<FunctionGraphVertex*>(this->getVertex(item.first));

        if(v->contains(index))
            return v;
    }

    return NULL;
}

void FunctionGraph::buildNode(int index, FunctionGraph::IndexQueue &indexqueue)
{
    auto it = std::next(m_document->begin(), index);

    if(it == m_document->end())
        return;

    std::unique_ptr<FunctionGraphVertex> fgv = std::make_unique<FunctionGraphVertex>(index);
    ListingItem* item = it->get();

    for( ; it != m_document->end(); it++, index++)
    {
        item = it->get();

        if(item->address == 0x080483F7)
        {
            int zzz = 0;
            zzz++;
        }

        if(this->vertexFromListingIndex(index))
            break;

        if(item->is(ListingItem::SymbolItem))
        {
            if(index == fgv->startidx) // Skip first label
                continue;

            SymbolPtr symbol = m_document->symbol(item->address);

            if(symbol->is(SymbolTypes::Code) && !symbol->isFunction())
                indexqueue.push(index);

            fgv->labelbreak = true;
            break;
        }

        if(!item->is(ListingItem::InstructionItem))
            break;

        fgv->endidx = index;
        InstructionPtr instruction = m_document->instruction(item->address);

        if(instruction->is(InstructionTypes::Jump))
        {
            for(address_t target : instruction->targets)
                indexqueue.push(m_document->indexOfSymbol(target));

            if(instruction->is(InstructionTypes::Conditional))
                indexqueue.push(index + 1);

            break;
        }

        if(instruction->is(InstructionTypes::Stop))
            break;
    }

    this->pushVertex(fgv.release());
}

s64 FunctionGraph::buildNodes(address_t startaddress)
{
    REDasm::ListingItem* item = m_document->functionStart(startaddress);

    if(!item)
        return -1;

    startaddress = item->address;
    s64 firstindex = m_document->indexOf(item) + 1; // Skip declaration

    IndexQueue queue;
    queue.push(firstindex);

    while(!queue.empty())
    {
        s64 index = queue.front();
        queue.pop();

        if(index == -1)
            continue;

        item = m_document->functionStart(m_document->itemAt(index));

        if(!item || (item->address != startaddress) || this->vertexFromListingIndex(index))
            continue;

        this->buildNode(index, queue);
    }

    return firstindex;
}

void FunctionGraph::buildEdges()
{
    for(auto vit = this->begin(); vit != this->end(); vit++)
    {
        FunctionGraphVertex* v = static_cast<FunctionGraphVertex*>(*vit);
        auto it = std::next(m_document->begin(), v->startidx);
        int index = v->startidx;

        if(v->labelbreak && (v->endidx + 1 < static_cast<s64>(m_document->size())))
            this->edge(v, this->vertexFromListingIndex(v->endidx + 1));

        for( ; (it != m_document->end()) && (index <= v->endidx); it++, index++)
        {
            ListingItem* item = it->get();

            if(!item->is(ListingItem::InstructionItem))
                continue;

            InstructionPtr instruction = m_document->instruction(item->address);

            if(!instruction->is(InstructionTypes::Jump))
                continue;

            for(address_t target : instruction->targets)
            {
                int tgtindex = m_document->indexOfSymbol(target);
                Graphing::Vertex* tov = this->vertexFromListingIndex(tgtindex);

                if(!tov)
                    continue;

                this->edge(v, tov);
                v->bTrue(tov);
            }

            if(instruction->is(InstructionTypes::Conditional))
            {
                Graphing::Vertex* tov = this->vertexFromListingIndex(index + 1);

                if(!tov)
                    continue;

                this->edge(v, tov);
                v->bFalse(tov);
            }
        }
    }
}

} // namespace Graphing
} // namespace REDasm
