#include "graph.h"

namespace REDasm {
namespace Graphing {

Graph::Graph(): m_currentid(0) { }

void Graph::addNode(Node *n)
{
    if(m_graph.find(n->id) != m_graph.end())
        return;

    n->id = this->getId();
    this->push_back(NodePtr(n));
    m_graph[n->id] = AdjacencyList();
}

void Graph::addEdge(Node *from, Node *to)
{
    if((m_graph.find(from->id) == m_graph.end()) || (m_graph.find(to->id) == m_graph.end()))
        return;

    m_graph[from->id].insert(to);
}

const AdjacencyList &Graph::edges(const NodePtr &np) const { return this->edges(np.get()); }
const AdjacencyList &Graph::edges(Node *n) const { return m_graph.at(n->id); }

int Graph::getId()
{
    return ++m_currentid;
}

} // namespace Graphing
} // namespace REDasm
