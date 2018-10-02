#ifndef NODEDATA_H
#define NODEDATA_H

#include <ogdf/basic/Graph.h>
#include <ogdf/basic/GraphAttributes.h>

namespace REDasm {
namespace Graphing {

class Graph;

struct NodeData
{
    NodeData();
    void bind(Graph* graph, ogdf::NodeElement *node);
    void resize(double width, double height);
    double x() const;
    double y() const;
    double width() const;
    double height() const;

    ogdf::GraphAttributes* attributes;
    ogdf::NodeElement* node;
};

} // namespace Graphing
} // namespace REDasm

#endif // NODEDATA_H
