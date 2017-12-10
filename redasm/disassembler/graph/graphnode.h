#ifndef GRAPHNODE_H
#define GRAPHNODE_H

#include "../../redasm.h"
#include <ogdf/basic/Graph.h>

namespace REDasm {

struct GraphNode
{
    GraphNode(): id(0), x(0), y(0), width(0), height(0), node(NULL) { }

    u64 id;
    s32 x, y, width, height;
    ogdf::NodeElement* node;
    std::set<address_t> block;
    std::vector< std::shared_ptr<GraphNode> > edges;

    address_t firstAddress() const { return *block.begin(); }
    address_t lastAddress() const { return *block.rbegin(); }
    bool hasEdges() const { return !edges.empty(); }
    bool isEmpty() const { return block.empty(); }
    bool contains(address_t address) const { return block.find(address) != block.end(); }
    void move(s32 x, s32 y) { this->x = x; this->y = y;}
    void resize(s32 width, s32 height) { this->width = width; this->height = height;}
};

typedef std::shared_ptr<GraphNode> GraphNodePtr;

} // namespace REDasm

#endif // GRAPHNODE_H
