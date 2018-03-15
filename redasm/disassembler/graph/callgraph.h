#ifndef CALLGRAPH_H
#define CALLGRAPH_H

#include "../types/listing.h"
#include "../../graph/graph.h"

namespace REDasm {

struct CallGraphVertex: public Graphing::Vertex
{
    SymbolPtr symbol;
    std::set<address_t> calls;

    CallGraphVertex(const SymbolPtr& symbol): Vertex(), symbol(symbol) { }
    virtual bool lessThan(Vertex* v) const { RE_UNUSED(v); return false; }
};

class CallGraph: public Graphing::Graph
{
    public:
        CallGraph(Listing& listing);
        void walk(address_t address);

    private:
        void buildVertices(address_t fromaddress);
        void buildEdges();

    private:
        Graphing::vertex_id_t vertexIdByAddress(address_t address) const;

    private:
        Listing& _listing;
        std::unordered_map<address_t, Graphing::vertex_id_t> _byaddress;
};

} // namespace REDasm

#endif // CALLGRAPH_H
