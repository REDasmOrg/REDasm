#include "graphview.h"
#include "graphviewmetrics.h"
#include <QMouseEvent>
#include <QScrollBar>

#define MINIMUM_SIZE 50

GraphView::GraphView(QWidget *parent): QScrollArea(parent)
{
    m_graphview_p = new GraphViewPrivate(this);
    this->setFrameStyle(QFrame::StyledPanel | QFrame::Sunken);
    this->setFocusProxy(m_graphview_p);
    this->setWidget(m_graphview_p);

    connect(m_graphview_p, &GraphViewPrivate::graphChanged, this, &GraphView::resizeGraphView);
}

void GraphView::render(REDasm::Graphing::Graph* graph)
{
    this->removeAll();

    REDasm::Graphing::LayeredGraph lgraph(graph);
    s64 y = GraphViewMetrics::itemPadding(), maxx = 0;

    for(REDasm::Graphing::VertexList& vl : lgraph)
    {
        s64 x = GraphViewMetrics::itemPadding(), maxheight = 0;

        for(REDasm::Graphing::Vertex* v : vl)
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
            x += sz.width() + GraphViewMetrics::itemPadding();

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

u64 GraphView::minimumSize() const { return MINIMUM_SIZE; }
bool GraphView::overviewMode() const { return m_graphview_p->overviewMode(); }
void GraphView::setOverviewMode(bool b) { m_graphview_p->setOverviewMode(b); }
void GraphView::setGraph(REDasm::Graphing::Graph *graph) { m_graphview_p->setGraph(graph); }
void GraphView::setGraphSize(const QSize &size) { m_graphview_p->setGraphSize(size); }

void GraphView::wheelEvent(QWheelEvent *e)
{
    if(e->modifiers() & Qt::ControlModifier)
        return;

    QScrollArea::wheelEvent(e);
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
        m_lastpos = e->pos();
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
        int xdelta = m_lastpos.x() - e->x();
        int ydelta = m_lastpos.y() - e->y();

        this->horizontalScrollBar()->setValue(this->horizontalScrollBar()->value() + xdelta);
        this->verticalScrollBar()->setValue(this->verticalScrollBar()->value() + ydelta);

        m_lastpos = e->pos();
    }
}

void GraphView::addItem(GraphItem *item) { m_graphview_p->addItem(item); }
void GraphView::removeAll() { return m_graphview_p->removeAll(); }

void GraphView::resizeGraphView()
{
    if(!m_graphview_p)
        return;

    QSize sz = m_graphview_p->graphSize();

    if(sz.width() < this->width())
        sz.setWidth(this->width());

    m_graphview_p->resize(sz);
}
