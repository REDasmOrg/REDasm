#include "graphview.h"
#include <QScrollBar>

GraphView::GraphView(QWidget *parent): QScrollArea(parent)
{
    QPalette p = this->palette();
    p.setColor(QPalette::Background, Qt::white);
    this->setAutoFillBackground(true);
    this->setPalette(p);

    this->_graphview_p = new GraphViewPrivate(this);
    this->setFrameStyle(QFrame::StyledPanel | QFrame::Sunken);
    this->setFocusPolicy(Qt::NoFocus);
    this->setFocusProxy(this->_graphview_p);
    this->setWidget(this->_graphview_p);

    connect(this->_graphview_p, &GraphViewPrivate::graphDrawed, this, &GraphView::resizeGraphView);
}

GraphItem *GraphView::addItem(GraphItem *item)
{
    return this->_graphview_p->addItem(item);
}

void GraphView::addEdge(GraphItem *fromitem, GraphItem *toitem)
{
    this->_graphview_p->addEdge(fromitem, toitem);
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
