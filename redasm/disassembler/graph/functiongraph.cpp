#include "functiongraph.h"
#include "../../graph/graph_layout.h"
#include <queue>

namespace REDasm {

FunctionGraph::FunctionGraph(Listing &listing): GraphT<FunctionGraphData, address_t>(), _startaddress(0), _endaddress(0), _listing(listing)
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

    this->setRootVertexKey(this->_startaddress);

    Graphing::GraphLayout gl(this);

    gl.layout([](Graph* g, Graphing::Vertex* v, Graphing::Vertex* e) -> bool {
        FunctionGraphType* fgt = static_cast<FunctionGraphType*>(g);
        FunctionGraphData *fgdv = fgt->getData(v), *fgde = fgt->getData(e);
        return fgde->start <= fgdv->start;
    });
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
        FunctionGraphData fgd(start);
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

                fgd.end = instruction->address;
                this->pushVertex(fgd, fgd.start);
                break;
            }

            if(instruction->is(InstructionTypes::Stop))
            {
                fgd.end = instruction->address;
                this->pushVertex(fgd, fgd.start);
                break;
            }

            it++;
        }
    }
}

void FunctionGraph::buildBlocksPass2()
{
    for(auto vit = this->dbegin(); vit != this->dend(); vit++)
    {
        FunctionGraphData* fgd = vit.getData();
        auto it = this->_listing.find(fgd->start);

        while(it.key < fgd->end)
        {
            InstructionPtr instruction = *it;
            Graphing::Vertex* v = this->findKey(instruction->endAddress());

            if(!v)
            {
                it++;
                continue;
            }

            fgd->end = instruction->address;
            fgd->bTrue(instruction->endAddress());
            this->edge(*vit, v);
            break;
        }
    }
}

void FunctionGraph::buildBlocksPass3()
{
    for(auto vit = this->dbegin(); vit != this->dend(); vit++)
    {
        FunctionGraphData* fgd = vit.getData();
        auto it = this->_listing.find(fgd->start);

        while(it.key <= fgd->end)
        {
            InstructionPtr instruction = *it;

            if(instruction->is(InstructionTypes::Jump) && instruction->hasTargets())
            {
                Graphing::Vertex* v = *vit;

                instruction->foreachTarget([this, &v, &fgd](address_t address) {
                    this->edge(v, this->findKey(address));
                    fgd->bTrue(address);
                });

                if(instruction->is(InstructionTypes::Conditional) && (instruction->endAddress() < this->_endaddress))
                {
                    this->edge(v, this->findKey(instruction->endAddress()));
                    fgd->bFalse(instruction->endAddress());
                }
            }

            it++;
        }
    }
}

} // namespace REDasm
