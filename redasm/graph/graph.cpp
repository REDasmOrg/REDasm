#include "graph.h"

namespace REDasm {
namespace Graphing {

Graph::Graph(): _currentid(0), _rootid(0)
{

}

void Graph::edge(Vertex *from, Vertex *to)
{
    if(!from || !to)
        return;

    this->edge(from->id, to->id);
}

void Graph::edge(vertex_id_t from, vertex_id_t to)
{
    this->_vertexmap.at(from)->edge(to);
}

size_t Graph::vertexCount() const
{
    return this->_vertexmap.size();
}

Vertex *Graph::rootVertex()
{
    if(!this->_rootid)
        return NULL;

    auto it = this->_vertexmap.find(this->_rootid);

    if(it == this->_vertexmap.end())
        return NULL;

    return it->second.get();
}

Vertex *Graph::getVertex(vertex_id_t id)
{
    return this->_vertexmap.at(id).get();
}

Vertex *Graph::getRealParentVertex(vertex_id_t id)
{
    Vertex* v = this->getVertex(id);

    while(v->isFake())
    {
        VertexSet vs = this->getParents(v);
        v = *vs.begin();
    }

    return v;
}

Vertex *Graph::getRealVertex(vertex_id_t id)
{
    Vertex* v = this->getVertex(id);

    while(v->isFake())
        v = this->getVertex(*v->edges.begin());

    return v;
}

VertexSet Graph::getParents(Vertex *v)
{
    VertexSet parents;

    for(auto& item : this->_vertexmap)
    {
        VertexPtr& vi = item.second;

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

    for(auto& item : this->_vertexmap)
        vl.push_back(item.second.get());

    return vl;
}

void Graph::setRootVertex(Vertex *v)
{
    if(!v)
    {
        this->_rootid = 0;
        return;
    }

    this->setRootVertex(v->id);
}

void Graph::setRootVertex(vertex_id_t id)
{
    this->_rootid = id;
}

void Graph::pushVertex(Vertex *v)
{
    v->id = ++this->_currentid;
    this->_vertexmap.emplace(v->id, v);
}

Vertex* Graph::pushFakeVertex(vertex_layer_t layer)
{
    Vertex* v = new Vertex();
    v->layout.layer = layer;
    v->layout.isfake = true;
    this->pushVertex(v);
    return v;
}

LayeredGraph::LayeredGraph(): std::vector<VertexList>(), _graph(NULL)
{

}

LayeredGraph::LayeredGraph(Graph *graph): std::vector<VertexList>()
{
    this->setGraph(graph);
}

vertex_layer_t LayeredGraph::lastLayer() const
{
    return this->size() - 1;
}

void LayeredGraph::setGraph(Graph *graph)
{
    this->_graph = graph;

    if(!this->_graph)
        return;

    this->clear();
    this->layerize();
    this->indicize();
}

void LayeredGraph::shuffle()
{
    for(VertexList& vl : *this)
        std::random_shuffle(vl.begin(), vl.end());
}

void LayeredGraph::layerize()
{
    std::map<vertex_layer_t, VertexList> bylayer;

    for(auto& item : this->_graph->_vertexmap)
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
