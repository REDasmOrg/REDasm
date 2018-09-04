#ifndef FUNCTIONGRAPH_H
#define FUNCTIONGRAPH_H

#include "../types/listing.h"
#include "../../graph/graph.h"

namespace REDasm {

struct FunctionGraphVertex: public Graphing::Vertex
{
    address_t start, end;

    FunctionGraphVertex(address_t start): Vertex(), start(start), end(start) { }
    virtual s64 compare(Vertex* v) const { return start - static_cast<FunctionGraphVertex*>(v)->start; }
    void bTrue(Graphing::Vertex* v) { edgeColor(v, "green"); }
    void bFalse(Graphing::Vertex* v) { edgeColor(v, "red"); }
};

class FunctionGraph: public Graphing::Graph
{
    public:
        FunctionGraph(InstructionsPool& listing);
        address_t startAddress() const;
        address_t endAddress() const;
        InstructionsPool& listing();
        void build(address_t address);

    private:
        FunctionGraphVertex* vertexFromAddress(address_t address);
        void buildBlocksPass1();
        void buildBlocksPass2();
        void buildBlocksPass3();

    private:
        address_t _startaddress, _endaddress;
        InstructionsPool& _listing;
};

} // namespace REDasm

#endif // FUNCTIONGRAPH_H
