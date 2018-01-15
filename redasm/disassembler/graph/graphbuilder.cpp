#include "graphbuilder.h"

namespace REDasm {

GraphBuilder::GraphBuilder(Listing &listing): _startaddress(0), _endaddress(0), _listing(listing)
{
}

const GraphNodePtr &GraphBuilder::rootNode()
{
    return this->_nodes[this->_startaddress];
}

const GraphNodePtr &GraphBuilder::getNode(address_t address)
{
    return this->_nodes[address];
}

GraphBuilder::NodeList GraphBuilder::getEdges(const GraphNodePtr &node) const
{
    auto it = this->_edges.find(node->address);

    if(it != this->_edges.end())
        return it->second;

    return NodeList();
}

void GraphBuilder::build(address_t address)
{
    if(!this->_listing.getFunctionBounds(address, &this->_startaddress, &this->_endaddress))
        return;

    this->buildNodes();

    std::for_each(this->_nodes.begin(), this->_nodes.end(), [this](const std::pair<address_t, const GraphNodePtr&>& item) {
        this->fillNode(item.second);
    });

    std::for_each(this->_nodes.begin(), this->_nodes.end(), [this](const std::pair<address_t, const GraphNodePtr&>& item) {
        this->addEdges(item.second);
    });
}

void GraphBuilder::buildNodes()
{
    auto it = this->_listing.find(this->_startaddress);

    while(it != this->_listing.end())
    {
        InstructionPtr instruction = *it;

        if(instruction->address >= this->_endaddress)
            break;

        if(instruction->is(InstructionTypes::Jump) && (instruction->endAddress() < this->_endaddress))
            this->addNode(instruction->endAddress());
        else if(instruction->blockIs(BlockTypes::BlockStart))
            this->addNode(instruction->address);

        it++;
    }
}

void GraphBuilder::fillNode(const GraphNodePtr& node)
{
    auto it = this->_listing.find(node->address);

    while(it != this->_listing.end())
    {
        if((it.key == this->_endaddress) || ((it.key != node->address) && (this->_nodes.find(it.key) != this->_nodes.end())))
            break;

        node->items.insert(it.key);
        it++;
    }
}

void GraphBuilder::addEdges(const GraphNodePtr &node)
{
    auto it = this->_listing.find(node->address);

    while(it != this->_listing.end())
    {
        InstructionPtr instruction = *it;

        if(!instruction->is(InstructionTypes::Jump) || !instruction->hasTargets())
        {
            it++;
            continue;
        }

        std::for_each(instruction->targets.begin(), instruction->targets.end(), [this, &node](address_t target) {
            this->addEdge(node, target);
        });

        this->addEdge(node, instruction->endAddress());
        it++;
    }
}

void GraphBuilder::addEdge(const GraphNodePtr& node, address_t target)
{
    if((target < this->_startaddress) || (target >= this->_endaddress))
        return;

    auto it = this->_edges.find(node->address);

    if(it != this->_edges.end())
    {
        it->second.insert(target);
        return;
    }

    NodeList nodes;
    nodes.insert(target);
    this->_edges[node->address] = nodes;
}

void GraphBuilder::addNode(address_t address)
{
    if(this->_nodes.find(address) != this->_nodes.end())
        return;

    this->_nodes[address] = std::make_unique<GraphNode>(address);
}

} // namespace REDasm
