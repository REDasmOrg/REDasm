#include "graphbuilder.h"
#include <queue>

namespace REDasm {

GraphBuilder::GraphBuilder(Listing &listing): _startaddress(0), _endaddress(0), _listing(listing)
{
}

u32 GraphBuilder::height() const
{
    return GraphBuilder::height(this->rootNode());
}

const GraphNodePtr &GraphBuilder::rootNode() const
{
    return this->_nodes.at(this->_startaddress);
}

const GraphNodePtr &GraphBuilder::getNode(address_t address)
{
    return this->_nodes[address];
}

void GraphBuilder::build(address_t address)
{
    if(!this->_listing.getFunctionBounds(address, &this->_startaddress, &this->_endaddress))
        return;

    this->buildNodesPass1(); // Build nodes
    this->buildNodesPass2(); // Check overlapping nodes
    this->buildNodesPass3(); // Elaborate node's edges
    this->buildNodesPass4(); // Elaborate node's incoming edges
}

u32 GraphBuilder::height(const GraphNodePtr &node)
{
    /* STUB */
}

void GraphBuilder::buildNodesPass1()
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
        GraphNodePtr node = std::make_unique<GraphNode>(start);
        auto it = this->_listing.find(start);

        while(it != this->_listing.end())
        {
            InstructionPtr instruction = *it;

            if(instruction->address >= this->_endaddress)
                break;

            if(instruction->is(InstructionTypes::Jump) && instruction->hasTargets())
            {
                instruction->foreachTarget([&queue, &node](address_t address) {
                    queue.push(address);
                });

                if(instruction->is(InstructionTypes::Conditional) && (instruction->endAddress() < this->_endaddress))
                    queue.push(instruction->endAddress());

                node->end = instruction->address;
                this->_nodes[start] = std::move(node);
                break;
            }

            if(instruction->is(InstructionTypes::Stop))
            {
                node->end = instruction->address;
                this->_nodes[start] = std::move(node);
                break;
            }

            it++;
        }
    }
}

void GraphBuilder::buildNodesPass2()
{
    for(auto nit = this->_nodes.begin(); nit != this->_nodes.end(); nit++)
    {
        const GraphNodePtr& node = nit->second;
        auto it = this->_listing.find(node->start);

        while(it.key < node->end)
        {
            InstructionPtr instruction = *it;

            if(this->_nodes.find(instruction->endAddress()) != this->_nodes.end())
            {
                node->end = instruction->address;
                node->bTrue(instruction->endAddress());
                break;
            }

            it++;
        }
    }
}

void GraphBuilder::buildNodesPass3()
{
    for(auto nit = this->_nodes.begin(); nit != this->_nodes.end(); nit++)
    {
        const GraphNodePtr& node = nit->second;
        auto it = this->_listing.find(node->start);

        while(it.key <= node->end)
        {
            InstructionPtr instruction = *it;

            if(instruction->is(InstructionTypes::Jump) && instruction->hasTargets())
            {
                instruction->foreachTarget([&node](address_t address) {
                    node->bTrue(address);
                });

                if(instruction->is(InstructionTypes::Conditional) && (instruction->endAddress() < this->_endaddress))
                    node->bFalse(instruction->endAddress());
            }

            it++;
        }
    }
}

void GraphBuilder::buildNodesPass4()
{
    for(auto nit = this->_nodes.begin(); nit != this->_nodes.end(); nit++)
    {
        const GraphNodePtr& node = nit->second;

        std::for_each(node->trueBranches.begin(), node->trueBranches.end(), [this, &node](address_t start) {
            auto it = this->_nodes.find(start);

            if((it == this->_nodes.end()) || (it->second == node))
                return;

            it->second->incoming(node->start);
        });

        std::for_each(node->falseBranches.begin(), node->falseBranches.end(), [this, &node](address_t start) {
            auto it = this->_nodes.find(start);

            if((it == this->_nodes.end()) || (it->second == node))
                return;

            it->second->incoming(node->start);
        });
    }
}

} // namespace REDasm
