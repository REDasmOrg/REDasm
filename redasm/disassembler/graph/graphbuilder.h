#ifndef GRAPHBUILDER_H
#define GRAPHBUILDER_H

#include <functional>
#include "../types/listing.h"
#include "graphnode.h"

namespace REDasm {

class GraphBuilder // Keep graph interface separated from Listing class
{
    public:
        typedef std::set<address_t> NodeList;

    private:
        typedef std::unordered_map<address_t, GraphNodePtr> Nodes;
        typedef std::unordered_map<address_t, NodeList> Edges;

    public:
        GraphBuilder(Listing& listing);
        const GraphNodePtr& rootNode();
        const GraphNodePtr& getNode(address_t address);
        NodeList getEdges(const GraphNodePtr& node) const;
        void build(address_t address);

    private:
        void buildNodes();
        void fillNode(const GraphNodePtr& node);
        void addEdges(const GraphNodePtr& node);
        void addEdge(const GraphNodePtr &node, address_t target);
        void addNode(address_t address);

    private:
        address_t _startaddress, _endaddress;
        Listing& _listing;
        Nodes _nodes;
        Edges _edges;

};

} // namespace REDasm

#endif // GRAPHBUILDER_H
