#ifndef GRAPHNODE_H
#define GRAPHNODE_H

#include "../../redasm.h"

namespace REDasm {

struct GraphNode
{
    // Data
    std::set<address_t> incomingNodes;
    std::set<address_t> trueBranches;
    std::set<address_t> falseBranches;
    address_t start, end;

    // Appeareance
    std::string color;

    GraphNode(address_t start): start(start), end(start), color("black") { }
    void incoming(address_t address) { incomingNodes.insert(address); }
    void bTrue(address_t address) { trueBranches.insert(address); }
    void bFalse(address_t address) { falseBranches.insert(address); }
};

typedef std::unique_ptr<GraphNode> GraphNodePtr;

} // namespace REDasm

#endif // GRAPHNODE_H
