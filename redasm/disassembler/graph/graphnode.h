#ifndef GRAPHNODE_H
#define GRAPHNODE_H

#include "../../redasm.h"

namespace REDasm {

struct GraphNode
{
    GraphNode(address_t address): address(address), color("black") { }

    // Data
    address_t address;
    std::set<address_t> items;

    // Appeareance
    std::string color;

    bool isEmpty() const { return items.empty(); }
    address_t firstAddress() const { return *items.begin(); }
    address_t lastAddress() const { return *items.rbegin(); }
};

typedef std::unique_ptr<GraphNode> GraphNodePtr;

} // namespace REDasm

#endif // GRAPHNODE_H
