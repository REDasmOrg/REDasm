#ifndef FUNCTIONGRAPH_H
#define FUNCTIONGRAPH_H

#include "../listing/listingdocument.h"
#include "../../graph/graph.h"
#include <queue>

namespace REDasm {
namespace Graphing {

struct FunctionGraphData: public NodeData
{
    s64 startidx, endidx;
    bool labelbreak;

    FunctionGraphData(s64 startidx): NodeData(), startidx(startidx), endidx(startidx), labelbreak(false) { }
    bool contains(s64 index) const { return (index >= startidx) && (index <= endidx); }
    int count() const { return (endidx - startidx) + 1; }
};

class FunctionGraph: public Graph
{
    private:
        typedef std::queue<address_t> AddressQueue;
        typedef std::queue<s64> IndexQueue;

    public:
        FunctionGraph(ListingDocument* document);
        ListingDocument* document();
        void build(address_t address);

    private:
        FunctionGraphData* vertexFromListingIndex(s64 index);
        void buildNodes(address_t startaddress);
        void buildNode(int index, IndexQueue &indexqueue);
        void buildEdges();

    private:
        ListingDocument* m_document;
};

} // namespace Graphing
} // namespace REDasm

#endif // FUNCTIONGRAPH_H
