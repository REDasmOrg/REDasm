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
                explicit iterator(Graph* graph, const VertexIterator& vertit): _graph(graph), _vertit(vertit) { update(); }
                iterator& operator++() { _vertit++; update(); return *this; }
                iterator operator++(int) { iterator copy = *this; _vertit++; update(); return copy; }
                bool operator==(const iterator& rhs) const { return _vertit == rhs._vertit; }
                bool operator!=(const iterator& rhs) const { return _vertit != rhs._vertit; }
                iterator& operator=(const iterator& rhs) { _vertit = rhs._vertit; update(); return *this; }
                Vertex* operator *() { return _graph->getVertex(id); }

            private:
                void update() { id = (_vertit == _graph->_vertexmap.end()) ? 0 : _vertit->first; }

            protected:
                Graph* _graph;
                VertexIterator _vertit;

            public:
                vertex_id_t id;
        };

    public:
        Graph();
        Graph::iterator begin() { return iterator(this, this->_vertexmap.begin()); }
        Graph::iterator end() { return iterator(this, this->_vertexmap.end()); }
        void edge(Vertex* from, Vertex* to);
        void edge(vertex_id_t from, vertex_id_t to);
        Vertex* rootVertex();
        Vertex* getVertex(vertex_id_t id);
        Vertex* getRealParentVertex(vertex_id_t id);
        Vertex* getRealVertex(vertex_id_t id);
        VertexSet getParents(Vertex* v);
        VertexList getVertexList() const;
        void setRootVertex(Vertex* v);
        void setRootVertex(vertex_id_t id);
        void pushVertex(Vertex* v);
        Vertex *pushFakeVertex(vertex_layer_t layer);

    protected:
        VertexMap _vertexmap;
        vertex_id_t _currentid, _rootid;
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
        Graph* _graph;
        vertex_layer_t _lastlayer;
};

typedef std::shared_ptr<LayeredGraph> LayeredGraphPtr;

} // namespace Graphing
} // namespace REDasm

#endif // GRAPH_H
