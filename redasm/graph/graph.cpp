#include "graph.h"

namespace REDasm {
namespace Graphing {

Graph::Graph(): _currentid(0), _rootid(0)
{

}

bool Graph::edge(Vertex *from, Vertex *to)
{
    return this->edge(from->id, to->id);
}

bool Graph::edge(vertex_id_t from, vertex_id_t to)
{
    if(from >= this->_vertexmap.size())
        return false;

    this->_vertexmap.at(from)->edges.insert(to);
    return true;
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

            parents.insert(this->getVertex(edge));
            break;
        }
    }

    return parents;
}

void Graph::setRootVertex(Vertex *v)
{
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

} // namespace Graph
} // namespace REDasm
