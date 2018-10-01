#ifndef FUNCTIONGRAPH_H
#define FUNCTIONGRAPH_H

#include "../listing/listingdocument.h"
#include "../../graph/graph.h"
#include <queue>

namespace REDasm {
namespace Graphing {

struct FunctionGraphVertex: public Graphing::Vertex
{
    s64 startidx, endidx;
    bool labelbreak;

    FunctionGraphVertex(s64 startidx): Vertex(), startidx(startidx), endidx(startidx), labelbreak(false) { }
    virtual s64 compare(Vertex* v) const { return startidx - static_cast<FunctionGraphVertex*>(v)->startidx; }
    bool contains(s64 index) const { return (index >= startidx) && (index <= endidx); }
    int count() const { return (endidx - startidx) + 1; }
    void bTrue(Graphing::Vertex* v) { edgeColor(v, "green"); }
    void bFalse(Graphing::Vertex* v) { edgeColor(v, "red"); }
};

class FunctionGraph: public Graphing::Graph
{
    private:
        typedef std::queue<address_t> AddressQueue;
        typedef std::queue<s64> IndexQueue;

    public:
        FunctionGraph(ListingDocument* document);
        ListingDocument* document();
        void build(address_t address);

    private:
        FunctionGraphVertex* vertexFromListingIndex(s64 index);
        s64 buildNodes(address_t startaddress);
        void buildNode(int index, IndexQueue &indexqueue);
        void buildEdges();

    private:
        ListingDocument* m_document;
};

} // namespace Graphing
} // namespace REDasm

#endif // FUNCTIONGRAPH_H
