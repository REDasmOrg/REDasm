#ifndef FUNCTIONGRAPH_H
#define FUNCTIONGRAPH_H

#include "../types/listing.h"
#include "../../graph/graph.h"

namespace REDasm {

struct FunctionGraphVertex: public Graphing::Vertex
{
    address_t start, end;
    Graphing::EdgeList trueBranches, falseBranches;

    FunctionGraphVertex(address_t start): Vertex(), start(start), end(start) { }
    virtual s64 compare(Vertex* v) const { return start - static_cast<FunctionGraphVertex*>(v)->start; }
    void bTrue(address_t address) { trueBranches.insert(address); }
    void bFalse(address_t address) { falseBranches.insert(address); }
};

class FunctionGraph: public Graphing::Graph
{
    public:
        FunctionGraph(Listing& listing);
        address_t startAddress() const;
        address_t endAddress() const;
        Listing& listing();
        void build(address_t address);

    private:
        FunctionGraphVertex* vertexFromAddress(address_t address);
        void buildBlocksPass1();
        void buildBlocksPass2();
        void buildBlocksPass3();

    private:
        address_t _startaddress, _endaddress;
        Listing& _listing;
};

} // namespace REDasm

#endif // FUNCTIONGRAPH_H
