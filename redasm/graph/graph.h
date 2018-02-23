#ifndef GRAPH_H
#define GRAPH_H

#include "../redasm.h"

namespace REDasm {
namespace Graphing {

typedef u64 vertex_id_t;
typedef std::set<vertex_id_t> EdgeList;

struct Vertex
{
    Vertex(vertex_id_t id);

    vertex_id_t id;
    EdgeList edges;

    u64 layer;
    std::string color;
};

typedef std::set<Vertex*> VertexSet;

class Graph
{
    protected:
        typedef std::unordered_map<vertex_id_t, Vertex> VertexMap;
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
        bool edge(Vertex* from, Vertex* to);
        bool edge(vertex_id_t from, vertex_id_t to);
        Vertex* rootVertex();
        Vertex* getVertex(vertex_id_t id);
        VertexSet getParents(Vertex* v);
        void setRootVertex(Vertex* v);
        void setRootVertex(vertex_id_t id);

    protected:
        VertexMap _vertexmap;
        vertex_id_t _currentid, _rootid;
};

template<typename T, typename U = size_t> class GraphT: public Graph
{
    private:
        typedef GraphT<T, U> GraphType;
        typedef std::unordered_map<vertex_id_t, T> VertexData;
        typedef std::unordered_map<U, Vertex*> VertexKeys;
        typedef typename VertexData::iterator VertexDataIterator;

    public:
        class data_iterator: public Graph::iterator {
            public:
                explicit data_iterator(GraphType* graph, const VertexIterator& vertit): Graph::iterator(graph, vertit) { }
                T* getData() { return static_cast<GraphType*>(_graph)->getData(id); }
        };

    public:
        GraphT(): Graph() { }
        GraphType::data_iterator dbegin() { return data_iterator(this, this->_vertexmap.begin()); }
        GraphType::data_iterator dend() { return data_iterator(this, this->_vertexmap.end()); }
        Vertex *findKey(U key) const;
        bool setRootVertexKey(U key);
        T* getData(Vertex* v) { return this->getData(v->id); }
        T* getData(vertex_id_t id);
        Vertex* pushVertex(const T& data, U key);
        Vertex* pushVertex(const T& data);

    private:
        VertexData _vertexdata;
        VertexKeys _vertexkeys;
};

template<typename T, typename U> Vertex* GraphT<T, U>::findKey(U key) const
{
    auto it = this->_vertexkeys.find(key);

    if(it == this->_vertexkeys.end())
        return NULL;

    return it->second;
}

template<typename T, typename U> bool GraphT<T, U>::setRootVertexKey(U key)
{
    auto it = this->_vertexkeys.find(key);

    if(it == this->_vertexkeys.end())
        return false;

    this->setRootVertex(it->second);
    return true;
}

template<typename T, typename U> T* GraphT<T, U>::getData(vertex_id_t id)
{
    auto it = this->_vertexdata.find(id);

    if(it == this->_vertexdata.end())
        return NULL;

    return &it->second;
}

template<typename T, typename U> Vertex* GraphT<T, U>::pushVertex(const T& data, U key)
{
    Vertex* v = this->pushVertex(data);
    this->_vertexkeys[key] = v;
    return v;
}

template<typename T, typename U> Vertex* GraphT<T, U>::pushVertex(const T& data)
{
    vertex_id_t id = ++this->_currentid;
    auto it = this->_vertexmap.emplace(id, id);
    this->_vertexdata.emplace(id, data);
    return &(it.first->second);
}

} // namespace Graphing
} // namespace REDasm

#endif // GRAPH_H
