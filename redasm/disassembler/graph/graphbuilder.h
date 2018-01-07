#ifndef GRAPHBUILDER_H
#define GRAPHBUILDER_H

//#include <ogdf/layered/SugiyamaLayout.h>
#include <functional>
#include "../types/listing.h"

namespace REDasm {

/*

class GraphBuilder // Keep graph interface separated from Listing class
{
    public:
        typedef ogdf::NodeElement Node;
        typedef ogdf::EdgeElement Edge;
        typedef std::set<address_t> Block;
        typedef std::map<address_t, ogdf::NodeElement*> Nodes;
        typedef std::list<ogdf::EdgeElement*> Edges;
        typedef std::map<ogdf::NodeElement*, Block> Blocks;

    public:
        GraphBuilder(Listing& listing);
        ogdf::GraphAttributes& graphAttributes();
        const Nodes &nodes();
        const Edges &edges();
        void position(Node *node, double& x, double& y) const;
        void iterateBlocks(std::function<void(Node*, const Block&, double&, double&)> cb);
        void build(address_t address);
        void layout();

    private:
        void checkReferences(const SymbolPtr& symbol, const Listing::FunctionPath &path);
        void checkFirst(ogdf::NodeElement *node);
        void checkLast(ogdf::NodeElement *node);
        void buildBlocks();
        void buildEdges();
        void buildNodes(const Listing::FunctionPath& path);
        void addEdge(ogdf::NodeElement* from, ogdf::NodeElement* to, ogdf::Color::Name colorname);
        address_t firstAddress(ogdf::NodeElement *node);
        address_t lastAddress(ogdf::NodeElement* node);
        ogdf::NodeElement* addNode(address_t address);
        ogdf::NodeElement* findNode(address_t address);

    private:
        address_t _currentaddress;
        Listing& _listing;
        ogdf::Graph _graph;
        ogdf::GraphAttributes _ga;
        Nodes _nodes;
        Blocks _blocks;
        Edges _edges;
};
*/

} // namespace REDasm

#endif // GRAPHBUILDER_H
