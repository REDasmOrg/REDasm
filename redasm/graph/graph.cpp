#include "graph.h"

namespace REDasm {
namespace Graphing {

Graph::Graph(): _currentid(0), _rootid(0)
{

}

void Graph::edge(Vertex *from, Vertex *to)
{
    this->edge(from->id, to->id);
}

void Graph::edge(vertex_id_t from, vertex_id_t to)
{
    this->_vertexmap.at(from)->edge(to);
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

void Graph::setRootVertex(Vertex *v)
{
    if(!v)
        this->_rootid = 0;

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

LayeredGraph::LayeredGraph(): std::map<vertex_layer_t, VertexList>(), _graph(NULL)
{

}

LayeredGraph::LayeredGraph(Graph *graph): std::map<vertex_layer_t, VertexList>(), _graph(graph)
{
    this->layerize();
    this->indicize();
}

vertex_layer_t LayeredGraph::lastLayer() const
{
    return this->rbegin()->first;
}

void LayeredGraph::layerize()
{
    for(auto& item : this->_graph->_vertexmap)
    {
        vertex_index_t index = -1;
        Vertex* v = item.second.get();
        auto it = this->find(v->layer());

        if(it == this->end())
        {
            VertexList vl;
            vl.push_back(v);
            this->insert(std::make_pair(v->layer(), vl));
            index = 0;
        }
        else
        {
            index = it->second.size();
            it->second.push_back(v);
        }

        if(v->index() == -1)
            v->layout.index = index;
    }
}

void LayeredGraph::indicize()
{
    for(auto it = this->begin(); it != this->end(); it++)
    {
        std::sort(it->second.begin(), it->second.end(), [](Vertex* v1, Vertex* v2) -> bool {
            return v1->index() < v2->index();
        });
    };
}

} // namespace Graph
} // namespace REDasm
