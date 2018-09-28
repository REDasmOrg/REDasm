#ifndef GRAPH_H
#define GRAPH_H

#include <deque>
#include "../redasm.h"
#include "vertex.h"

namespace REDasm {
namespace Graphing {

typedef std::set<Vertex*> VertexSet;
typedef std::deque<Vertex*> VertexList;

class Graph
{
    friend class LayeredGraph;

    protected:
        typedef std::unique_ptr<Vertex> VertexPtr;
        typedef std::unordered_map<vertex_id_t, VertexPtr> VertexMap;
        typedef typename VertexMap::iterator VertexIterator;

    public:
        class iterator: public std::iterator<std::random_access_iterator_tag, Vertex*> {
            public:
                explicit iterator(Graph* graph, const VertexIterator& vertit): m_graph(graph), m_vertit(vertit) { update(); }
                iterator& operator++() { m_vertit++; update(); return *this; }
                iterator operator++(int) { iterator copy = *this; m_vertit++; update(); return copy; }
                bool operator==(const iterator& rhs) const { return m_vertit == rhs.m_vertit; }
                bool operator!=(const iterator& rhs) const { return m_vertit != rhs.m_vertit; }
                iterator& operator=(const iterator& rhs) { m_vertit = rhs.m_vertit; update(); return *this; }
                Vertex* operator *() { return m_graph->getVertex(id); }

            private:
                void update() { id = (m_vertit == m_graph->m_vertexmap.end()) ? 0 : m_vertit->first; }

            protected:
                Graph* m_graph;
                VertexIterator m_vertit;

            public:
                vertex_id_t id;
        };

    public:
        Graph();
        Graph::iterator begin() { return iterator(this, this->m_vertexmap.begin()); }
        Graph::iterator end() { return iterator(this, this->m_vertexmap.end()); }
        void edge(Vertex* from, Vertex* to);
        void edge(vertex_id_t from, vertex_id_t to);
        size_t vertexCount() const;
        Vertex* rootVertex();
        Vertex* getVertex(vertex_id_t id);
        Vertex* getRealParentVertex(Vertex *v);
        Vertex* getRealVertex(Vertex *v);
        VertexSet getParents(const Vertex *v) const;
        VertexList getVertexList() const;
        void setRootVertex(Vertex* v);
        void setRootVertex(vertex_id_t id);
        void pushVertex(Vertex* v);
        Vertex* pushFakeVertex(vertex_layer_t layer);

    protected:
        void layout();

    protected:
        VertexMap m_vertexmap;
        vertex_id_t m_currentid, m_rootid;
};

class LayeredGraph: public std::vector<VertexList>
{
    public:
        LayeredGraph();
        LayeredGraph(Graph* graph);
        vertex_layer_t lastLayer() const;
        void shuffle();

    private:
        void layerize();
        void indicize();

    private:
        Graph* m_graph;
};

typedef std::shared_ptr<LayeredGraph> LayeredGraphPtr;

} // namespace Graphing
} // namespace REDasm

#endif // GRAPH_H
