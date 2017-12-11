#include "graphbuilder.h"
#include <ogdf/layered/OptimalHierarchyLayout.h>
#include <ogdf/layered/OptimalRanking.h>
#include <ogdf/layered/MedianHeuristic.h>
#include <ogdf/fileformats/GraphIO.h>

#define BOTTOM_OF(node) (node->y + node->height + GRAPH_PADDING)
#define CENTER_X(node)  (node->x + node->width / 2)
#define MIDDLE_W(node)  (node->width / 2)
#define QUARTER_W(node) (node->width / 4)

namespace REDasm {

using namespace ogdf;

GraphBuilder::GraphBuilder(Listing &listing): _currentaddress(0), _listing(listing)
{
    this->_ga.init(this->_graph, GraphAttributes::nodeGraphics |
                                 GraphAttributes::edgeGraphics |
                                 GraphAttributes::edgeArrow    |
                                 GraphAttributes::edgeStyle);
}

GraphAttributes &GraphBuilder::graphAttributes()
{
    return this->_ga;
}

const GraphBuilder::Nodes &GraphBuilder::nodes()
{
    return this->_nodes;
}

const GraphBuilder::Edges &GraphBuilder::edges()
{
    return this->_edges;
}

void GraphBuilder::position(GraphBuilder::Node* node, double &x, double &y) const
{
    x = this->_ga.x(node);
    y = this->_ga.y(node);
}

void GraphBuilder::iterateBlocks(std::function<void(GraphBuilder::Node*, const GraphBuilder::Block&, double&, double&)> cb)
{
    double w = 0, h = 0;

    for(auto it = this->_blocks.begin(); it != this->_blocks.end(); it++)
    {
        NodeElement* node = it->first;
        cb(node, it->second, w, h);

        this->_ga.width(node) = w;
        this->_ga.height(node) = h;
    }
}

void GraphBuilder::build(address_t address)
{
    auto fnit = this->_listing.findFunction(address);

    if(fnit == this->_listing._paths.end())
        return;

    const Listing::FunctionPath& path = fnit->second;

    if(path.empty() || (*path.begin() == this->_currentaddress))
        return;

    this->_currentaddress = *path.begin();
    this->buildNodes(path);
}

void GraphBuilder::layout()
{
    OptimalHierarchyLayout* ohl = new OptimalHierarchyLayout();
    ohl->nodeDistance(10.0);
    ohl->layerDistance(20.0);

    SugiyamaLayout sl;
    sl.alignSiblings(true);
    sl.setLayout(ohl);
    sl.call(this->_ga);

    //GraphIO::drawSVG(this->_ga, "/home/davide/graph.svg");
}

void GraphBuilder::checkReferences(const SymbolPtr &symbol, const Listing::FunctionPath& path)
{
    ReferenceTable* referencetable = this->_listing.referenceTable();
    ReferenceVector refs = referencetable->referencesToVector(symbol);

    for(auto it = refs.begin(); it != refs.end(); it++)
    {
        if(path.find(*it) == path.end())
            continue;

        InstructionPtr instruction = this->_listing[*it];

        if(!instruction->is(InstructionTypes::Conditional | InstructionTypes::Jump))
            continue;

        if(path.find(instruction->endAddress()) == path.end())
            continue;

        instruction = this->_listing[instruction->endAddress()];
        this->addNode(instruction->address);
    }
}

void GraphBuilder::checkFirst(NodeElement* node)
{
    ReferenceTable* referencetable = this->_listing.referenceTable();
    InstructionPtr instruction = this->_listing[this->firstAddress(node)];
    ReferenceVector refs = referencetable->referencesToVector(instruction->address);

    std::for_each(refs.begin(), refs.end(), [this, node](address_t address) {
        NodeElement* refnode = this->findNode(address);

        if(refnode)
            this->addEdge(refnode, node, Color::Name::Blue);
    });
}

void GraphBuilder::checkLast(NodeElement* node)
{
    InstructionPtr instruction = this->_listing[this->lastAddress(node)];

    if(!instruction->is(InstructionTypes::Jump))
    {
        if(instruction->is(InstructionTypes::Stop))
            return;

        NodeElement* nextnode = this->findNode(instruction->endAddress());

        if(nextnode)
            this->addEdge(node, nextnode, Color::Name::Blue);

        return;
    }

    std::for_each(instruction->targets.begin(), instruction->targets.end(), [this, node](address_t target) {
        auto nit = this->_nodes.find(target);

        if(nit != this->_nodes.end())
            this->addEdge(node, nit->second, Color::Name::Green);
    });

    if(instruction->is(InstructionTypes::Conditional))
    {
        auto nit = this->_nodes.find(instruction->endAddress());

        if(nit != this->_nodes.end())
            this->addEdge(node, nit->second, Color::Name::Red);
    }
}

void GraphBuilder::buildBlocks()
{
    std::for_each(this->_nodes.begin(), this->_nodes.end(), [this](const std::pair<address_t, NodeElement*>& item) {
        auto it = this->_listing.find(item.first);
        Block& block = this->_blocks[item.second];
        InstructionPtr instruction;

        do {
            if(it == this->_listing.end())
                break;

            instruction = *it;

            if(!block.empty() && (this->_nodes.find(instruction->address) != this->_nodes.end()))
                break;

            block.insert(instruction->address);
            it++;
        }
        while(!instruction || !instruction->is(InstructionTypes::Stop));
    });
}

void GraphBuilder::buildEdges()
{
    for(auto it = this->_nodes.begin(); it != this->_nodes.end(); it++)
    {
        this->checkFirst(it->second);
        this->checkLast(it->second);
    }
}

void GraphBuilder::buildNodes(const Listing::FunctionPath &path)
{
    SymbolTable* symboltable = this->_listing.symbolTable();
    this->addNode(*path.begin());

    for(auto it = path.begin(); it != path.end(); it++)
    {
        SymbolPtr symbol = symboltable->symbol(*it);

        if(!IS_LABEL(symbol) || (path.find(*it) == path.end()))
            continue;

        this->addNode(*it);
        this->checkReferences(symbol, path);
    }

    this->buildBlocks();
    this->buildEdges();
}

void GraphBuilder::addEdge(NodeElement *from, NodeElement *to, Color::Name colorname)
{
    EdgeElement* edge = this->_graph.newEdge(from, to);
    this->_ga.strokeColor(edge) = colorname;
    this->_edges.push_back(edge);
}

address_t GraphBuilder::firstAddress(NodeElement *node)
{
    const Block& block = this->_blocks[node];
    return *block.begin();
}

address_t GraphBuilder::lastAddress(NodeElement *node)
{
    const Block& block = this->_blocks[node];
    return *block.rbegin();
}

NodeElement* GraphBuilder::findNode(address_t address)
{
    for(auto it = this->_nodes.begin(); it != this->_nodes.end(); it++)
    {
        const Block& block = this->_blocks[it->second];

        if(block.find(address) != block.end())
            return it->second;
    }

    return NULL;
}

NodeElement *GraphBuilder::addNode(address_t address)
{
    auto it = this->_nodes.find(address);

    if(it != this->_nodes.end())
        return it->second;

    NodeElement* n = this->_graph.newNode();
    this->_nodes[address] = n;
    this->_blocks[n] = Block();
    return n;
}

} // namespace REDasm
