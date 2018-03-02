#include "graphview.h"
#include <QMouseEvent>
#include <QScrollBar>

#define ITEM_PADDING 25
#define MINIMUM_SIZE 50

GraphView::GraphView(QWidget *parent): QScrollArea(parent)
{
    this->_graphview_p = new GraphViewPrivate(this);
    this->setFrameStyle(QFrame::StyledPanel | QFrame::Sunken);
    this->setFocusProxy(this->_graphview_p);
    this->setWidget(this->_graphview_p);

    connect(this->_graphview_p, &GraphViewPrivate::graphChanged, this, &GraphView::resizeGraphView);
}

u64 GraphView::itemPadding() const
{
    return ITEM_PADDING;
}

u64 GraphView::minimumSize() const
{
    return MINIMUM_SIZE;
}

void GraphView::addItem(GraphItem *item)
{
    this->_graphview_p->addItem(item);
}

void GraphView::removeAll()
{
    return this->_graphview_p->removeAll();
}

bool GraphView::overviewMode() const
{
    return this->_graphview_p->overviewMode();
}

void GraphView::setOverviewMode(bool b)
{
    this->_graphview_p->setOverviewMode(b);
}

void GraphView::setGraphSize(const QSize &size)
{
    this->_graphview_p->setGraphSize(size);
}

void GraphView::mousePressEvent(QMouseEvent *e)
{
    QScrollArea::mousePressEvent(e);

    if(e->button() == Qt::LeftButton)
    {
        this->_lastpos = e->pos();
        this->setCursor(QCursor(Qt::ClosedHandCursor));
    }
}

void GraphView::mouseReleaseEvent(QMouseEvent *e)
{
    QScrollArea::mouseReleaseEvent(e);

    if(e->button() == Qt::LeftButton)
        this->setCursor(QCursor(Qt::ArrowCursor));
}

void GraphView::mouseMoveEvent(QMouseEvent *e)
{
    QScrollArea::mouseMoveEvent(e);

    if(e->buttons() & Qt::LeftButton)
    {
        int xdelta = this->_lastpos.x() - e->x();
        int ydelta = this->_lastpos.y() - e->y();

        this->horizontalScrollBar()->setValue(this->horizontalScrollBar()->value() + xdelta);
        this->verticalScrollBar()->setValue(this->verticalScrollBar()->value() + ydelta);

        this->_lastpos = e->pos();
    }
}

void GraphView::resizeGraphView()
{
    QSize sz = this->_graphview_p->graphSize();
    this->_graphview_p->resize(sz);
}
