#include "graph_layout.h"
#include "graph_genetic.h"
#include <queue>

namespace REDasm {
namespace Graphing {

GraphLayout::GraphLayout(Graph *graph): m_graph(graph)
{

}

void GraphLayout::layout()
{
    if(!m_graph->rootVertex())
        return;

    this->removeLoops();
    this->assignLayers();
    this->insertFakeVertices();
    this->minimizeCrossings();
    this->restoreLoops();
}

void GraphLayout::removeLoops()
{
    for(Vertex* v1 : *m_graph)
    {
        for(auto it = v1->edges.begin(); it != v1->edges.end(); )
        {
            Vertex* v2 = m_graph->getVertex(*it);

            if(v2->lessThan(v1) || v2->equalsTo(v1))
                it = v1->edges.erase(it);
            else
                it++;
        }
    }
}

void GraphLayout::assignLayers()
{
    std::queue<Vertex*> pending;
    pending.push(m_graph->rootVertex());

    while(!pending.empty())
    {
        Vertex* v = pending.front();
        pending.pop();

        VertexSet parents = m_graph->getParents(v);
        v->layout.layer = parents.empty() ? 0 : GraphLayout::maxLayer(parents) + 1;

        for(vertex_id_t edge : v->edges)
            pending.push(m_graph->getVertex(edge));
    }
}

void GraphLayout::insertFakeVertices()
{
    VertexList vl = m_graph->getVertexList();

    for(Vertex* v1 : vl)
    {
        for(auto it = v1->edges.begin(); it != v1->edges.end(); )
        {
            vertex_id_t edge = *it;
            Vertex* v2 = m_graph->getVertex(edge);

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
                v = m_graph->pushFakeVertex(layer);
                m_graph->edge(pv, v);
                pv = v;
                layer++;
            }

            m_graph->edge(pv, v2);
            it = v1->edges.erase(it);
        }
    }
}

void GraphLayout::minimizeCrossings()
{
    GraphGenetic gc(m_graph);
    GraphGenetic::individual_fitness_t res = gc.grow(NULL);
    LayeredGraphPtr lgraph;

    if(gc.generation() > 1)
        lgraph = res.first;
    else
        lgraph = std::make_shared<LayeredGraph>(m_graph);

    for(VertexList& vl : *lgraph)
    {
        for(size_t i = 0; i < vl.size(); i++)
            vl[i]->index(i);
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
