#include "graph_layout.h"
#include <queue>

namespace REDasm {
namespace Graphing {

GraphLayout::GraphLayout(Graph *graph): _graph(graph)
{

}

void GraphLayout::layout()
{
    if(!this->_graph->rootVertex())
        return;

    this->removeLoops();
    this->assignLayers();
    this->insertFakeVertices();
}

void GraphLayout::removeLoops()
{
    for(Vertex* v1 : *this->_graph)
    {
        for(auto it = v1->edges.begin(); it != v1->edges.end(); )
        {
            Vertex* v2 = this->_graph->getVertex(*it);

            if(v2->lessThan(v1))
                it = v1->edges.erase(it);
            else
                it++;
        }
    }
}

void GraphLayout::assignLayers()
{
    std::queue<Vertex*> pending;
    pending.push(this->_graph->rootVertex());

    while(!pending.empty())
    {
        Vertex* v = pending.front();
        pending.pop();

        VertexSet parents = this->_graph->getParents(v);
        v->layout.layer = parents.empty() ? 0 : GraphLayout::maxLayer(parents) + 1;

        for(vertex_id_t edge : v->edges)
            pending.push(this->_graph->getVertex(edge));
    }
}

void GraphLayout::insertFakeVertices()
{
    for(Vertex* v1 : *this->_graph)
    {
        for(vertex_id_t edge : v1->edges)
        {
            Vertex* v2 = this->_graph->getVertex(edge);
            u64 diff = std::max(v1->layout.layer, v2->layout.layer) -
                       std::min(v1->layout.layer, v2->layout.layer);

            if(diff <= 1)
                continue;

            //TODO: Insert fake vertices
        }
    }
}

vertex_layer_t GraphLayout::maxLayer(const VertexSet& vs)
{
    vertex_layer_t layer = 0;

    for(Vertex* v : vs)
        layer = std::max(layer, v->layout.layer);

    return layer;
}

} // namespace Graphing
} // namespace REDasm
