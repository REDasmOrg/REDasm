#ifndef GRAPHLAYOUT_H
#define GRAPHLAYOUT_H

// http://blog.disy.net/sugiyama-method
// http://publications.lib.chalmers.se/records/fulltext/161388.pdf
// https://drive.google.com/file/d/1uAAch1SxLLVBJ53ZX-zX4AnwzwhcXcEM/view

#include "functiongraph.h"

namespace REDasm {

class GraphLayout
{
    private:
        typedef std::vector<address_t> Columns;
        typedef std::list<Columns> Rows;

    public:
        GraphLayout();
        void layout(const FunctionGraph& gb);

    private: // Layout steps
        void cloneGraph(const FunctionGraph& gb);
        void removeCycles();
        void assignLayers(const FunctionGraph &gb);
        void inserFakeNodes(const FunctionGraph& gb);

    private:
        void longestPath(address_t source, address_t target, std::list<address_t>& path) const;
        //void removeParentLoopsFrom(const GraphNodePtr& node, Graphing::EdgeList& edges);
        //void removeLoopsFrom(const GraphNodePtr& node, Graphing::EdgeList& edges);
};

} // namespace REDasm

#endif // GRAPHLAYOUT_H
