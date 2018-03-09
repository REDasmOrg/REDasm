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
    public:
        GraphLayout(Graph* graph);
        void layout();

    private:
        void removeLoops();
        void assignLayers();
        void insertFakeVertices();
        void minimizeCrossings();
        void restoreLoops();

    private:
        static vertex_layer_t maxLayer(const VertexSet &vs);

    private:
        Graph* _graph;
};

} // namespace Graphing
} // namespace REDasm

#endif // GRAPH_LAYOUT_H
