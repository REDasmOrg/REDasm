#include "graph.h"
#include <ogdf/layered/SugiyamaLayout.h>
#include <ogdf/layered/SugiyamaLayout.h>
#include <ogdf/layered/OptimalHierarchyLayout.h>
#include <ogdf/layered/OptimalRanking.h>
#include <ogdf/layered/MedianHeuristic.h>
#include <ogdf/fileformats/GraphIO.h>
#include "../redasm.h"

namespace REDasm {
namespace Graphing {

Graph::Graph()
{
    m_attributes.init(m_graph, ogdf::GraphAttributes::nodeGraphics |
                               ogdf::GraphAttributes::edgeGraphics |
                               ogdf::GraphAttributes::edgeStyle); // |
                               //ogdf::GraphAttributes::edgeArrow);
}
double Graph::width() {  return m_attributes.boundingBox().width(); }
double Graph::height() { return m_attributes.boundingBox().height(); }

ogdf::GraphAttributes *Graph::attributes() { return &m_attributes; }
const Graph::NodeDataList &Graph::nodes() const { return m_nodelist; }
const Graph::EdgeList &Graph::edges() const { return m_edgelist; }

void Graph::addNode(NodeData *data)
{
    ogdf::NodeElement* node = m_graph.newNode();
    data->bind(this, node);
    m_nodelist.push_back(std::make_unique<NodeData>(data));
}

void Graph::addEdge(NodeData *from, NodeData *to, const ogdf::Color &color)
{
    ogdf::EdgeElement* edge = m_graph.newEdge(from->node, to->node);
    m_attributes.strokeColor(edge) = color;
    //m_attributes.arrowType(edge) = ogdf::EdgeArrow::Last;
    m_edgelist.push_back(edge);
}

const ogdf::Color &Graph::color(ogdf::EdgeElement *edge) const { return m_attributes.strokeColor(edge); }

ogdf::DPolyline Graph::polyline(ogdf::EdgeElement *edge) const
{
    ogdf::DPolyline p = m_attributes.bends(edge);
    ogdf::NodeElement *src = edge->source(), *tgt = edge->target();

    p.pushFront(ogdf::DPoint(m_attributes.x(src) + (m_attributes.width(src) / 2),
                             m_attributes.y(src) + m_attributes.height(src)));

    p.pushBack(ogdf::DPoint(m_attributes.x(tgt) + (m_attributes.width(tgt) / 2),
                             m_attributes.y(tgt)));

    return p;
}

void Graph::layout()
{
    ogdf::OptimalHierarchyLayout* optlayout = new ogdf::OptimalHierarchyLayout();
    optlayout->nodeDistance(25.0);
    optlayout->layerDistance(5.0);
    optlayout->weightBalancing(0.8);

    ogdf::SugiyamaLayout slayout;
    slayout.setRanking(new ogdf::OptimalRanking());
    slayout.setCrossMin(new ogdf::MedianHeuristic());
    slayout.setLayout(optlayout);
    slayout.call(m_attributes);

    ogdf::GraphIO::drawSVG(m_attributes, "/home/davide/graph.svg");
}

} // namespace Graphing
} // namespace REDasm
