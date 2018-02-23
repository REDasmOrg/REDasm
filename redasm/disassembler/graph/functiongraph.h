#ifndef FUNCTIONGRAPH_H
#define FUNCTIONGRAPH_H

#include "../types/listing.h"
#include "../../graph/graph.h"

namespace REDasm {

struct FunctionGraphData
{
    address_t start, end;
    Graphing::EdgeList trueBranches;
    Graphing::EdgeList falseBranches;

    FunctionGraphData(address_t start): start(start), end(start) { }
    void bTrue(address_t address) { trueBranches.insert(address); }
    void bFalse(address_t address) { falseBranches.insert(address); }
};

typedef Graphing::GraphT<FunctionGraphData, address_t> FunctionGraphType;

class FunctionGraph: public FunctionGraphType
{
    public:
        FunctionGraph(Listing& listing);
        address_t startAddress() const;
        address_t endAddress() const;
        void build(address_t address);

    private:
        void buildBlocksPass1();
        void buildBlocksPass2();
        void buildBlocksPass3();

    private:
        address_t _startaddress, _endaddress;
        Listing& _listing;
};

} // namespace REDasm

#endif // FUNCTIONGRAPH_H
