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

void GraphView::render(const REDasm::Graphing::Graph* graph)
{
    this->removeAll();

    REDasm::Graphing::VertexByLayer bylayer = graph->sortByLayer();
    s64 y = this->itemPadding(), maxx = 0;

    for(auto& item : bylayer)
    {
        s64 x = this->itemPadding(), maxheight = 0;

        for(REDasm::Graphing::Vertex* v : item.second)
        {
            GraphItem* gi = NULL;

            if(v->isFake())
            {
                gi = new GraphItem(v, this);
                gi->resize(this->minimumSize(), 0);
            }
            else
                gi = this->createItem(v);

            gi->move(x, y);

            QSize sz = gi->size();
            x += sz.width() + this->itemPadding();

            if(sz.height() > maxheight)
                maxheight = sz.height();

            this->addItem(gi);
        }

        if(x > maxx)
            maxx = x;

        y += maxheight + this->minimumSize();
    }

    this->setGraphSize(QSize(maxx + this->minimumSize(), y + this->minimumSize()));
}

u64 GraphView::itemPadding() const
{
    return ITEM_PADDING;
}

u64 GraphView::minimumSize() const
{
    return MINIMUM_SIZE;
}

bool GraphView::overviewMode() const
{
    return this->_graphview_p->overviewMode();
}

void GraphView::setOverviewMode(bool b)
{
    this->_graphview_p->setOverviewMode(b);
}

void GraphView::setGraph(REDasm::Graphing::Graph *graph)
{
    this->_graphview_p->setGraph(graph);
}

void GraphView::setGraphSize(const QSize &size)
{
    this->_graphview_p->setGraphSize(size);
}

void GraphView::resizeEvent(QResizeEvent *e)
{
    QScrollArea::resizeEvent(e);

    this->resizeGraphView();
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

void GraphView::addItem(GraphItem *item)
{
    this->_graphview_p->addItem(item);
}

void GraphView::removeAll()
{
    return this->_graphview_p->removeAll();
}

void GraphView::resizeGraphView()
{
    if(!this->_graphview_p)
        return;

    QSize sz = this->_graphview_p->graphSize();

    if(sz.width() < this->width())
        sz.setWidth(this->width());

    this->_graphview_p->resize(sz);
}
