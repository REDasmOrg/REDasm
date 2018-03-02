#ifndef VERTEX_H
#define VERTEX_H

#include "../redasm.h"

namespace REDasm {
namespace Graphing {

typedef u64 vertex_id_t;
typedef u64 vertex_layer_t;
typedef std::set<vertex_id_t> EdgeList;
typedef std::unordered_map<Graphing::vertex_id_t, std::string> EdgeColors;

struct Vertex
{
    vertex_id_t id;
    EdgeList edges;
    EdgeColors edgeColors;
    std::string color;

    struct {
        vertex_layer_t layer;
        bool isfake;
    } layout;

    Vertex(): id(0), color("black") { layout.layer = 0; layout.isfake = false; }
    virtual s64 compare(Vertex* v) const { return id - v->id; }
    vertex_id_t layer() const { return layout.layer; }
    bool isFake() const { return layout.isfake; }
    bool equalsTo(Vertex* v) const { return compare(v) == 0; }
    bool lessThan(Vertex* v) const { return compare(v) < 0; }
    bool greaterThan(Vertex* v) const { return compare(v) > 0; }
    void edgeColor(Vertex* v, const std::string& color) { edgeColors[v->id] = color; }

    std::string edgeColor(Vertex* tov) const {
        auto it = edgeColors.find(tov->id);

        if(it != edgeColors.end())
            return it->second;

        return "black";
    }
};

} // namespace Graphing
} // namespace REDasm

#endif // VERTEX_H
