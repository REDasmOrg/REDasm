#include "graph.h"
#include "graph_layout.h"

namespace REDasm {
namespace Graphing {

Graph::Graph(): m_currentid(0), m_rootid(0) { }

void Graph::edge(Vertex *from, Vertex *to)
{
    if(!from || !to)
        return;

    this->edge(from->id, to->id);
}

void Graph::edge(vertex_id_t from, vertex_id_t to)
{
    if(!from || !to)
        return;

    m_vertexmap.at(from)->edge(to);
}

size_t Graph::vertexCount() const { return m_vertexmap.size(); }

Vertex *Graph::rootVertex()
{
    if(!m_rootid)
        return NULL;

    auto it = m_vertexmap.find(m_rootid);

    if(it == m_vertexmap.end())
        return NULL;

    return it->second.get();
}

Vertex *Graph::getVertex(vertex_id_t id) { return m_vertexmap.at(id).get(); }

Vertex *Graph::getRealParentVertex(Vertex* v)
{
    while(v->isFake())
    {
        VertexSet vs = this->getParents(v);
        v = *vs.begin();
    }

    return v;
}

Vertex *Graph::getRealVertex(Vertex* v)
{
    while(v->isFake())
        v = this->getVertex(*v->edges.begin());

    return v;
}

VertexSet Graph::getParents(const Vertex *v) const
{
    VertexSet parents;

    for(auto& item : m_vertexmap)
    {
        const VertexPtr& vi = item.second;

        if(vi->id == v->id)
            continue;

        for(vertex_id_t edge : vi->edges)
        {
            if(edge != v->id)
                continue;

            parents.insert(vi.get());
            break;
        }
    }

    return parents;
}

VertexList Graph::getVertexList() const
{
    VertexList vl;

    for(auto& item : m_vertexmap)
        vl.push_back(item.second.get());

    return vl;
}

void Graph::setRootVertex(Vertex *v)
{
    if(!v)
    {
        m_rootid = 0;
        return;
    }

    this->setRootVertex(v->id);
}

void Graph::setRootVertex(vertex_id_t id) { m_rootid = id; }

void Graph::pushVertex(Vertex *v)
{
    v->id = ++m_currentid;
    v->graph = this;
    m_vertexmap.emplace(v->id, VertexPtr(v));
}

Vertex* Graph::pushFakeVertex(vertex_layer_t layer)
{
    Vertex* v = new Vertex();
    v->layout.layer = layer;
    v->layout.isfake = true;
    this->pushVertex(v);
    return v;
}

void Graph::layout()
{
    Graphing::GraphLayout gl(this);
    gl.layout();
}

LayeredGraph::LayeredGraph(): std::vector<VertexList>(), m_graph(NULL) { }

LayeredGraph::LayeredGraph(Graph *graph): std::vector<VertexList>(), m_graph(graph)
{
    if(!m_graph)
        return;

    this->clear();
    this->layerize();
    this->indicize();
}

vertex_layer_t LayeredGraph::lastLayer() const { return this->size() - 1; }

void LayeredGraph::shuffle()
{
    for(VertexList& vl : *this)
        std::random_shuffle(vl.begin(), vl.end());
}

void LayeredGraph::layerize()
{
    std::map<vertex_layer_t, VertexList> bylayer;

    for(auto& item : m_graph->m_vertexmap)
    {
        Vertex* v = item.second.get();
        auto it = bylayer.find(v->layer());

        if(it == bylayer.end())
        {
            VertexList vl;
            vl.push_back(v);
            bylayer.insert(std::make_pair(v->layer(), vl));
        }
        else
            it->second.push_back(v);
    }

    for(auto& item : bylayer)
        this->push_back(item.second);
}

void LayeredGraph::indicize()
{
    for(VertexList& vl : *this)
    {
        std::sort(vl.begin(), vl.end(), [](Vertex* v1, Vertex* v2) {
            return v1->index() < v2->index();
        });
    }
}

} // namespace Graph
} // namespace REDasm
