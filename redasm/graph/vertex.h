#ifndef VERTEX_H
#define VERTEX_H

#include "../redasm.h"

namespace REDasm {
namespace Graphing {

typedef u64 vertex_id_t;
typedef u64 vertex_layer_t;
typedef std::set<vertex_id_t> EdgeList;

struct Vertex
{
    vertex_id_t id;
    EdgeList edges;
    std::string color;

    struct {
        vertex_layer_t layer;
        bool isfake;
    } layout;

    Vertex(): id(0), color("black") { layout.layer = 0; layout.isfake = false; }
    virtual s64 compare(Vertex* v) const { return id - v->id; }
    bool isFake() const { return layout.isfake; }
    bool equalsTo(Vertex* v) const { return compare(v) == 0; }
    bool lessThan(Vertex* v) const { return compare(v) < 0; }
    bool greaterThan(Vertex* v) const { return compare(v) > 0; }
};

} // namespace Graphing
} // namespace REDasm

#endif // VERTEX_H
