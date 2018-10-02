#include "nodedata.h"
#include "graph.h"

namespace REDasm {
namespace Graphing {

NodeData::NodeData(): attributes(NULL), node(NULL) { }

void NodeData::bind(Graph *graph, ogdf::NodeElement *node)
{
    if(attributes)
        return;

     attributes = graph->attributes();
     this->node = node;
}

void NodeData::resize(double width, double height)
{
    attributes->width(node) = width;
    attributes->height(node) = height;
}

double NodeData::x() const { return attributes->x(node); }
double NodeData::y() const { return attributes->y(node); }
double NodeData::width() const { return attributes->width(node); }
double NodeData::height() const { return attributes->height(node); }

} // namespace Graphing
} // namespace REDasm
