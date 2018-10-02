#ifndef GRAPH_H
#define GRAPH_H

#include <functional>
#include <memory>
#include <list>
#include <ogdf/basic/Graph.h>
#include <ogdf/basic/GraphAttributes.h>
#include "nodedata.h"

namespace REDasm {
namespace Graphing {

class Graph
{
    public:
        typedef std::unique_ptr<NodeData> NodeDataPtr;
        typedef std::list<NodeDataPtr> NodeDataList;
        typedef std::list<ogdf::EdgeElement*> EdgeList;

    public:
        Graph();
        double width();
        double height();
        ogdf::GraphAttributes* attributes();
        const NodeDataList& nodes() const;
        const EdgeList& edges() const;
        void addNode(NodeData* data);
        void addEdge(NodeData* from, NodeData* to);
        ogdf::DPolyline polyline(ogdf::EdgeElement* edge);
        virtual void layout();

    protected:
        ogdf::Graph m_graph;
        ogdf::GraphAttributes m_attributes;
        NodeDataList m_nodelist;
        EdgeList m_edgelist;
};

} // namespace Graphing
} // namespace REDasm

#endif // GRAPH_H
