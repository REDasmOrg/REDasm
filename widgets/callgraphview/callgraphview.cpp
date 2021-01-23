#include "callgraphview.h"
#include "callgraphitem.h"
#include <rdapi/graph/layout.h>

CallGraphView::CallGraphView(const RDContextPtr& ctx, QWidget* parent) : GraphView(parent), m_context(ctx)
{
    m_callgraph.reset(RDCallGraph_Create(ctx.get()));
}

void CallGraphView::walk(rd_address address)
{
    RDCallGraph_Walk(m_callgraph.get(), address);
    this->setGraph(m_callgraph.get());
}

void CallGraphView::onFetchMode(rd_address address)
{
    RDCallGraph_WalkFrom(m_callgraph.get(), address);
    this->updateGraph();
}

GraphViewItem* CallGraphView::createItem(RDGraphNode n, const RDGraph* g)
{
    auto* cgi = new CallGraphItem(m_context, n, g);
    connect(cgi, &CallGraphItem::fetchMore, this, &CallGraphView::onFetchMode);
    return cgi;
}
