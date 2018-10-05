#ifndef FUNCTIONGRAPH_H
#define FUNCTIONGRAPH_H

#include "../listing/listingdocument.h"
#include "../../graph/graph.h"
#include <queue>

namespace REDasm {
namespace Graphing {

struct FunctionBlock: public Node
{
    s64 startidx, endidx;
    bool labelbreak;

    std::unordered_map<const FunctionBlock*, std::string> colors;

    FunctionBlock(s64 startidx): startidx(startidx), endidx(startidx), labelbreak(false) { }
    bool contains(s64 index) const { return (index >= startidx) && (index <= endidx); }
    int count() const { return (endidx - startidx) + 1; }
    void bTrue(const FunctionBlock* v) { colors[v] = "green"; }
    void bFalse(const FunctionBlock* v) { colors[v] = "red"; }

    std::string color(const FunctionBlock* to) const {
        auto it = colors.find(to);

        if(it == colors.end())
            return "blue";

        return it->second;
    }
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
        FunctionBlock* vertexFromListingIndex(s64 index);
        void buildVertices(address_t startaddress);
        void buildNode(int index, IndexQueue &indexqueue);
        void buildEdges();

    private:
        ListingDocument* m_document;
};

} // namespace Graphing
} // namespace REDasm

#endif // FUNCTIONGRAPH_H
