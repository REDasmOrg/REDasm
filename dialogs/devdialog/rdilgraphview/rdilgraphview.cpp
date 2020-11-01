#include "rdilgraphview.h"
#include "rdilelementitem.h"

RDILGraphView::RDILGraphView(QWidget* parent): GraphView(parent)
{
    this->setFrameShape(QFrame::StyledPanel);
}

GraphViewItem* RDILGraphView::createItem(RDGraphNode n, const RDGraph* g) { return new RDILElementItem(n, g); }
