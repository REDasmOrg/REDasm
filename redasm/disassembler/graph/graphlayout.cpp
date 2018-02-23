#include "graphlayout.h"

namespace REDasm {

GraphLayout::GraphLayout()
{

}

void GraphLayout::layout(const FunctionGraph &gb)
{
    this->cloneGraph(gb);
    this->removeCycles();
    this->assignLayers(gb);
}

void GraphLayout::cloneGraph(const FunctionGraph &gb)
{
    //for(auto& item : gb._nodes)
        //this->_clonedgraph[item.first] = std::make_unique<GraphNode>(*item.second);
}

void GraphLayout::removeCycles()
{
    /*
    for(auto& item : this->_clonedgraph)
    {
        this->removeLoopsFrom(item.second, item.second->trueBranches);
        this->removeLoopsFrom(item.second, item.second->falseBranches);
        this->removeParentLoopsFrom(item.second, item.second->parentNodes);
    }
    */
}

void GraphLayout::assignLayers(const FunctionGraph& gb)
{
    /*
    std::stack<address_t> pending;
    pending.push(gb.startAddress());

    while(!pending.empty())
    {
        const GraphNodePtr& node = this->_clonedgraph.at(pending.top());
        pending.pop();

        if(node->hasParents())
        {
            const GraphNodePtr& parentnode = this->_clonedgraph.at(*node->parentNodes.begin());
            node->layer = parentnode->layer + 1;
        }
        else
            node->layer = 0;

        for(address_t edge : node->edges())
            pending.push(edge);
    }
    */
}

void GraphLayout::inserFakeNodes(const FunctionGraph &gb)
{

}

void GraphLayout::longestPath(address_t source, address_t target, std::list<address_t> &path) const
{
    /*
    std::set<address_t> q;
    std::unordered_map<address_t, address_t> prev;
    std::unordered_map<address_t, u64> dist;

    for(auto& item : this->_clonedgraph)
    {
        dist[item.first] = 0;
        q.insert(item.first);
    }

    dist[source] = 1;

    while(!q.empty())
    {
        address_t address = 0, distance = 0;

        for(address_t u : q)
        {
            if(dist[u] <= distance)
                continue;

            address = u;
            distance = dist[u];
        }

        if(address == target)
            break;

        q.erase(address);
        const GraphNodePtr& node = this->_clonedgraph.at(address);

        for(auto edge : node->edges())
        {
            const GraphNodePtr& edgenode = this->_clonedgraph.at(edge);
            u64 adjdistance = distance + node->distance(edgenode);

            if(adjdistance < dist[edgenode->start])
                continue;

            dist[edgenode->start] = adjdistance;
            prev[edgenode->start] = address;
        }
    }

    address_t u = target;

    while(u != source)
    {
        path.push_front(u);
        u = prev[u];
    }

    path.push_front(u);
    */
}

/*
void GraphLayout::removeParentLoopsFrom(const GraphNodePtr &node, Graphing::EdgeList &edges)
{
    for(auto it = edges.begin(); it != edges.end(); )
    {
        if(*it >= node->start)
            it = edges.erase(it);
        else
            it++;
    }
}

void GraphLayout::removeLoopsFrom(const GraphNodePtr &node, Graphing::EdgeList &edges)
{
    for(auto it = edges.begin(); it != edges.end(); )
    {
        if(*it <= node->start)
            it = edges.erase(it);
        else
            it++;
    }
}
*/

} // namespace REDasm
