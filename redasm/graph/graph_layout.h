#ifndef GRAPH_LAYOUT_H
#define GRAPH_LAYOUT_H

// http://blog.disy.net/sugiyama-method
// http://publications.lib.chalmers.se/records/fulltext/161388.pdf
// https://drive.google.com/file/d/1uAAch1SxLLVBJ53ZX-zX4AnwzwhcXcEM/view

#include "../redasm.h"
#include "graph.h"

namespace REDasm {
namespace Graphing {

class GraphLayout
{
    private:
        typedef std::function<bool(Graph*, Vertex*, Vertex*)> RemoveCallback;

    public:
        GraphLayout(Graph* graph);
        void layout();

    private:
        void removeLoops();
        void assignLayers();
        void insertFakeVertices();

    private:
        static u64 maxLayer(const VertexSet &vs);

    private:
        Graph* _graph;
};

} // namespace Graphing
} // namespace REDasm

#endif // GRAPH_LAYOUT_H
