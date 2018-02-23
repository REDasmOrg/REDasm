#ifndef GRAPHNODE_H
#define GRAPHNODE_H

#include "../../redasm.h"
#include "../../graph/graph.h"

namespace REDasm {

struct GraphData
{
    address_t start, end;
    Graphing::EdgeList trueBranches;
    Graphing::EdgeList falseBranches;

    GraphData(address_t start): start(start), end(start) { }
    void bTrue(address_t address) { trueBranches.insert(address); }
    void bFalse(address_t address) { falseBranches.insert(address); }
};

struct GraphNode
{
    // Data
    Graphing::EdgeList parentNodes;
    Graphing::EdgeList trueBranches;
    Graphing::EdgeList falseBranches;
    address_t start, end;

    // Layout
    u64 layer;

    // Appeareance
    std::string color;

    GraphNode(address_t start): start(start), end(start), layer(0), color("black") { }
    bool hasParents() const { return !parentNodes.empty(); }
    void parent(address_t address) { parentNodes.insert(address); }
    void bTrue(address_t address) { trueBranches.insert(address); }
    void bFalse(address_t address) { falseBranches.insert(address); }
    u64 distance(const std::unique_ptr<GraphNode>& tonode) const { return std::max(tonode->start, start) - std::min(tonode->start, start); }

    Graphing::EdgeList edges() const {
        Graphing::EdgeList e;

        for(address_t address: trueBranches)
            e.insert(address);

        for(address_t address: falseBranches)
            e.insert(address);

        return e;
    }
};

typedef std::unique_ptr<GraphNode> GraphNodePtr;

} // namespace REDasm

#endif // GRAPHNODE_H
