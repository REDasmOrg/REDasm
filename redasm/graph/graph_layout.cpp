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
    this->restoreLoops();
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
        if(v1->edges.empty())
            continue;

        vertex_id_t lastedge = *v1->edges.rbegin();

        for(auto it = v1->edges.begin(); it != v1->edges.end(); )
        {
            vertex_id_t edge = *it;

            if(edge > lastedge) // Don't check fake edges
                break;

            Vertex* v2 = this->_graph->getVertex(edge);

            if((v2->layer() <= v1->layer()) || ((v2->layer() - v1->layer()) <= 1))
            {
                it++;
                continue;
            }

            vertex_layer_t layer = v1->layer() + 1;
            Vertex *pv = v1, *v = NULL;

            while(layer < v2->layer())
            {
                v = this->_graph->pushFakeVertex(layer);
                this->_graph->edge(pv, v);
                pv = v;
                layer++;
            }

            this->_graph->edge(pv, v2);
            it = v1->edges.erase(it);
        }
    }
}

void GraphLayout::restoreLoops()
{

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
