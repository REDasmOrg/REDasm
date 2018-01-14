#ifndef GRAPHNODE_H
#define GRAPHNODE_H

#include "../../redasm.h"

namespace REDasm {

struct GraphNode
{
    GraphNode(address_t address): address(address), color("black") { }

    address_t address;
    std::string color;
    std::set<address_t> items;
};

typedef std::unique_ptr<GraphNode> GraphNodePtr;

} // namespace REDasm

#endif // GRAPHNODE_H
