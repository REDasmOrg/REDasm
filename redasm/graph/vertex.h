#ifndef VERTEX_H
#define VERTEX_H

#include "../redasm.h"
#include <deque>

namespace REDasm {
namespace Graphing {

typedef u64 vertex_id_t;
typedef u64 vertex_layer_t;
typedef ssize_t vertex_index_t;
typedef std::deque<vertex_id_t> EdgeList;
typedef std::unordered_map<Graphing::vertex_id_t, std::string> EdgeColors;

struct Vertex
{
    vertex_id_t id;
    EdgeList edges;
    EdgeColors edgeColors;
    std::string color;

    struct {
        vertex_layer_t layer;
        vertex_index_t index;
        bool isfake;
    } layout;

    Vertex(): id(0), color("black") { layout = { 0, -1, false }; }
    virtual s64 compare(Vertex* v) const { return id - v->id; }
    vertex_id_t layer() const { return layout.layer; }
    vertex_id_t index() const { return layout.index; }
    void index(vertex_index_t index) { layout.index = index; }
    bool isFake() const { return layout.isfake; }
    bool equalsTo(Vertex* v) const { return compare(v) == 0; }
    bool lessThan(Vertex* v) const { return compare(v) < 0; }
    bool greaterThan(Vertex* v) const { return compare(v) > 0; }
    void edgeColor(Vertex* v, const std::string& color) { edgeColors[v->id] = color; }

    std::string edgeColor(Vertex* tov) const {
        auto it = edgeColors.find(tov->id);

        if(it != edgeColors.end())
            return it->second;

        return "blue";
    }

    void edge(vertex_id_t e) {
        if(std::find(edges.begin(), edges.end(), e) != edges.end())
            return;

        edges.push_back(e);
    }
};

} // namespace Graphing
} // namespace REDasm

#endif // VERTEX_H
