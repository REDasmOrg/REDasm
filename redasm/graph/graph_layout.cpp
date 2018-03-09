#include "graph_layout.h"
#include <iostream>
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
    this->minimizeCrossings();
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

        for(auto it = v1->edges.begin(); it != v1->edges.end(); )
        {
            vertex_id_t edge = *it;
            Vertex* v2 = this->_graph->getVertex(edge);

            if(v2->isFake()) // Don't continue through fake edges
                break;

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

void GraphLayout::minimizeCrossings()
{
    u64 c = this->crossingCount();

    if(!c)
        return;
}

void GraphLayout::restoreLoops()
{

}

u64 GraphLayout::crossingCount() const
{
    u64 crossings = 0;
    LayeredGraph lgraph(this->_graph);

    for(vertex_layer_t layer = 0; layer < lgraph.lastLayer(); layer++)
        crossings += this->crossingCount(lgraph.at(layer));

    return crossings;
}

u64 GraphLayout::crossingCount(const VertexList &layer1) const
{
    u64 count = 0;

    for(size_t i = 0; i < (layer1.size() - 1); i++)
    {
        Vertex *v1 = layer1[i], *v2 = layer1[i + 1];

        for(vertex_id_t edge1 : v1->edges)
        {
            Vertex* ve1 = this->_graph->getVertex(edge1);

            for(vertex_id_t edge2 : v2->edges)
            {
                if(!linesCrossing(v1, ve1, v2, this->_graph->getVertex(edge2)))
                    continue;

                count++;
            }
        }
    }

    return count;
}

bool GraphLayout::linesCrossing(Vertex* a1, Vertex* a2, Vertex* b1, Vertex* b2)
{
    return (a1->index() < b1->index() && a2->index() > b2->index()) ||
           (a1->index() > b1->index() && a2->index() < b2->index());
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
