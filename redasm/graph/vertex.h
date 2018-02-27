#ifndef VERTEX_H
#define VERTEX_H

#include "../redasm.h"

namespace REDasm {
namespace Graphing {

typedef u64 vertex_id_t;
typedef std::set<vertex_id_t> EdgeList;

struct Vertex
{
    vertex_id_t id;
    u64 layer;
    EdgeList edges;
    std::string color;

    Vertex(): id(0), layer(0), color("black") { }
    virtual s64 compare(Vertex* v) const { return id - v->id; }
    bool equalsTo(Vertex* v) const { return compare(v) == 0; }
    bool lessThan(Vertex* v) const { return compare(v) < 0; }
    bool greaterThan(Vertex* v) const { return compare(v) > 0; }
};

} // namespace Graphing
} // namespace REDasm

#endif // VERTEX_H
