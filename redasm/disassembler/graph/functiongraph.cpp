#include "functiongraph.h"
#include "../../graph/graph_layout.h"
#include <queue>

namespace REDasm {

FunctionGraph::FunctionGraph(ListingDocument* document): Graph(), m_startaddress(0), m_endaddress(0), m_listing(document) { }
address_t FunctionGraph::startAddress() const { return m_startaddress; }
address_t FunctionGraph::endAddress() const { return m_endaddress; }
ListingDocument* FunctionGraph::document() { return m_listing; }

void FunctionGraph::build(address_t address)
{
    /*
    if(!this->m_listing.getFunctionBounds(address, &this->m_startaddress, &this->m_endaddress))
        return;
        */

    this->buildBlocksPass1(); // Build nodes
    this->buildBlocksPass2(); // Check overlapping nodes
    this->buildBlocksPass3(); // Elaborate node's edges
    this->setRootVertex(this->vertexFromAddress(m_startaddress));
    this->layout();
}

FunctionGraphVertex *FunctionGraph::vertexFromAddress(address_t address)
{
    for(auto& item : m_vertexmap)
    {
       FunctionGraphVertex* v = static_cast<FunctionGraphVertex*>(this->getVertex(item.first));

        if(v->start == address)
            return v;
    }

    return NULL;
}

void FunctionGraph::buildBlocksPass1()
{
    /*
    std::queue<address_t> queue;
    std::set<address_t> visited;

    queue.push(this->m_startaddress);

    while(!queue.empty())
    {
        address_t start = queue.front();
        queue.pop();

        if(visited.find(start) != visited.end())
            continue;

        visited.insert(start);
        FunctionGraphVertex* v = new FunctionGraphVertex(start);
        auto it = this->m_listing.find(start);

        while(it != this->m_listing.end())
        {
            InstructionPtr instruction = *it;

            if(instruction->address >= this->m_endaddress)
                break;

            if(instruction->is(InstructionTypes::Jump) && instruction->hasTargets())
            {
                instruction->foreachTarget([&queue](address_t address) {
                    queue.push(address);
                });

                if(instruction->is(InstructionTypes::Conditional) && (instruction->endAddress() < this->m_endaddress))
                    queue.push(instruction->endAddress());

                v->end = instruction->address;
                this->pushVertex(v);
                break;
            }

            if(instruction->is(InstructionTypes::Stop))
            {
                v->end = instruction->address;
                this->pushVertex(v);
                break;
            }

            it++;
        }
    }
    */
}

void FunctionGraph::buildBlocksPass2()
{
    /*
    for(auto vit = this->begin(); vit != this->end(); vit++)
    {
        FunctionGraphVertex* v1 = static_cast<FunctionGraphVertex*>(*vit);
        auto it = this->m_listing.find(v1->start);

        while(it.key < v1->end)
        {
            InstructionPtr instruction = *it;
            FunctionGraphVertex* v2 = this->vertexFromAddress(instruction->endAddress());

            if(!v2)
            {
                it++;
                continue;
            }

            v1->end = instruction->address;
            this->edge(v1, v2);
            break;
        }
    }
    */
}

void FunctionGraph::buildBlocksPass3()
{
    /*
    for(auto vit = this->begin(); vit != this->end(); vit++)
    {
        FunctionGraphVertex* v1 = static_cast<FunctionGraphVertex*>(*vit);
        auto it = this->m_listing.find(v1->start);

        while(it.key <= v1->end)
        {
            InstructionPtr instruction = *it;

            if(instruction->is(InstructionTypes::Jump) && instruction->hasTargets())
            {
                Graphing::Vertex* v2 = *vit;

                instruction->foreachTarget([this, &v2, &v1](address_t address) {
                    Graphing::Vertex* v = this->vertexFromAddress(address);
                    this->edge(v2, v);
                    v1->bTrue(v);
                });

                if(instruction->is(InstructionTypes::Conditional) && (instruction->endAddress() < this->m_endaddress))
                {
                    Graphing::Vertex* v = this->vertexFromAddress(instruction->endAddress());
                    this->edge(v2, v);
                    v1->bFalse(v);
                }
            }

            it++;
        }
    }
    */
}

} // namespace REDasm
