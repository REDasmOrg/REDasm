#ifndef FUNCTIONGRAPH_H
#define FUNCTIONGRAPH_H

#include "../listing/listingdocument.h"
#include "../../graph/graph.h"
#include <queue>

namespace REDasm {
namespace Graphing {

struct FunctionGraphVertex: public Graphing::Vertex
{
    address_t start, end;
    int startidx, endidx;

    FunctionGraphVertex(address_t start): Vertex(), start(start), end(start), startidx(-1), endidx(-1) { }
    virtual s64 compare(Vertex* v) const { return start - static_cast<FunctionGraphVertex*>(v)->start; }
    int count() const { return endidx - startidx; }
    void bTrue(Graphing::Vertex* v) { edgeColor(v, "green"); }
    void bFalse(Graphing::Vertex* v) { edgeColor(v, "red"); }
};

class FunctionGraph: public Graphing::Graph
{
    private:
        typedef std::queue<address_t> AddressQueue;

    public:
        FunctionGraph(ListingDocument* document);
        ListingDocument* document();
        void build(address_t address);

    private:
        FunctionGraphVertex* vertexFromAddress(address_t address);
        void buildNode(address_t address, AddressQueue& addressqueue);
        void buildNodes(address_t startaddress);
        void buildEdges();

    private:
        ListingDocument* m_document;
};

} // namespace Graphing
} // namespace REDasm

#endif // FUNCTIONGRAPH_H
