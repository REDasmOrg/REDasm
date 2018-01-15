#include "graphview.h"
#include <QScrollBar>

GraphView::GraphView(QWidget *parent): QScrollArea(parent)
{
    this->_graphview_p = new GraphViewPrivate(this);
    this->setFrameStyle(QFrame::StyledPanel | QFrame::Sunken);
    this->setFocusPolicy(Qt::NoFocus);
    this->setFocusProxy(this->_graphview_p);
    this->setWidget(this->_graphview_p);

    connect(this->_graphview_p, &GraphViewPrivate::graphDrawed, this, &GraphView::resizeGraphView);
}

GraphItem *GraphView::addRoot(GraphItem *item)
{
    return this->_graphview_p->addRoot(item);
}

void GraphView::addEdge(GraphItem *fromitem, GraphItem *toitem)
{
    this->_graphview_p->addEdge(fromitem, toitem);
}

void GraphView::removeAll()
{
    return this->_graphview_p->removeAll();
}

void GraphView::beginInsertion()
{
    return this->_graphview_p->beginInsertion();
}

void GraphView::endInsertion()
{
    return this->_graphview_p->endInsertion();
}

bool GraphView::overviewMode() const
{
    return this->_graphview_p->overviewMode();
}

void GraphView::setOverviewMode(bool b)
{
    this->_graphview_p->setOverviewMode(b);
}

void GraphView::resizeGraphView()
{
    QSize sz = this->_graphview_p->graphSize();
    this->_graphview_p->resize(sz);
}
