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
    this->_vertexmap.at(from)->edges.insert(to);
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

VertexByLayer Graph::sortByLayer() const
{
    VertexByLayer bylayer;

    for(auto& item : this->_vertexmap)
    {
        Vertex* v = item.second.get();
        auto it = bylayer.find(v->layout.layer);

        if(it == bylayer.end())
        {
            VertexList vl;
            vl.push_back(v);
            bylayer[v->layout.layer] = vl;
        }
        else
            it->second.push_back(v);
    }

    return bylayer;
}

} // namespace Graph
} // namespace REDasm
