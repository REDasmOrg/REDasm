#include "functiongraph.h"
#include "../../graph/graph_layout.h"
#include <queue>

namespace REDasm {

FunctionGraph::FunctionGraph(Listing &listing): Graph(), _startaddress(0), _endaddress(0), _listing(listing)
{
}

address_t FunctionGraph::startAddress() const
{
    return this->_startaddress;
}

address_t FunctionGraph::endAddress() const
{
    return this->_endaddress;
}

void FunctionGraph::build(address_t address)
{
    if(!this->_listing.getFunctionBounds(address, &this->_startaddress, &this->_endaddress))
        return;

    this->buildBlocksPass1(); // Build nodes
    this->buildBlocksPass2(); // Check overlapping nodes
    this->buildBlocksPass3(); // Elaborate node's edges

    //this->setRootVertexKey(this->_startaddress);

    Graphing::GraphLayout gl(this);
    gl.layout();
}

FunctionGraphVertex *FunctionGraph::vertexFromAddress(address_t address)
{
    for(auto& item : this->_vertexmap)
    {
       FunctionGraphVertex* v = static_cast<FunctionGraphVertex*>(this->getVertex(item.first));

        if(v->start == address)
            return v;
    }

    return NULL;
}

void FunctionGraph::buildBlocksPass1()
{
    std::queue<address_t> queue;
    std::set<address_t> visited;

    queue.push(this->_startaddress);

    while(!queue.empty())
    {
        address_t start = queue.front();
        queue.pop();

        if(visited.find(start) != visited.end())
            continue;

        visited.insert(start);
        FunctionGraphVertex* v = new FunctionGraphVertex(start);
        auto it = this->_listing.find(start);

        while(it != this->_listing.end())
        {
            InstructionPtr instruction = *it;

            if(instruction->address >= this->_endaddress)
                break;

            if(instruction->is(InstructionTypes::Jump) && instruction->hasTargets())
            {
                instruction->foreachTarget([&queue](address_t address) {
                    queue.push(address);
                });

                if(instruction->is(InstructionTypes::Conditional) && (instruction->endAddress() < this->_endaddress))
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
}

void FunctionGraph::buildBlocksPass2()
{
    for(auto vit = this->begin(); vit != this->end(); vit++)
    {
        FunctionGraphVertex* v1 = static_cast<FunctionGraphVertex*>(*vit);
        auto it = this->_listing.find(v1->start);

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
            v1->bTrue(instruction->endAddress());
            this->edge(v1, v2);
            break;
        }
    }
}

void FunctionGraph::buildBlocksPass3()
{
    for(auto vit = this->begin(); vit != this->end(); vit++)
    {
        FunctionGraphVertex* v1 = static_cast<FunctionGraphVertex*>(*vit);
        auto it = this->_listing.find(v1->start);

        while(it.key <= v1->end)
        {
            InstructionPtr instruction = *it;

            if(instruction->is(InstructionTypes::Jump) && instruction->hasTargets())
            {
                Graphing::Vertex* v2 = *vit;

                instruction->foreachTarget([this, &v2, &v1](address_t address) {
                    this->edge(v2, this->vertexFromAddress(address));
                    v1->bTrue(address);
                });

                if(instruction->is(InstructionTypes::Conditional) && (instruction->endAddress() < this->_endaddress))
                {
                    this->edge(v2, this->vertexFromAddress(instruction->endAddress()));
                    v1->bFalse(instruction->endAddress());
                }
            }

            it++;
        }
    }
}

} // namespace REDasm
