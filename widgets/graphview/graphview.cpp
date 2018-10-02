#include "graphview.h"
#include "graphmetrics.h"
#include "../../redasm/redasm.h"
#include <QtGui>
#include <QtWidgets>

#define MINIMUM_SIZE 50
#define DROP_SHADOW_SIZE(x) x, x, x, x
#define DROP_SHADOW_VALUE 8
#define DROP_SHADOW_ARG   DROP_SHADOW_SIZE(DROP_SHADOW_VALUE)
#define ZOOM_FACTOR_STEP  0.050

GraphView::GraphView(QWidget *parent): QAbstractScrollArea(parent)
{
    this->setFrameStyle(QFrame::StyledPanel | QFrame::Sunken);
}

void GraphView::setGraph(REDasm::Graphing::Graph* graph)
{
    m_graph = std::make_unique<REDasm::Graphing::Graph>(graph);
    m_items.clear();

    this->horizontalScrollBar()->setValue(0);
    this->verticalScrollBar()->setValue(0);

    for(auto& item : m_graph->nodes())
        m_items.push_back(this->createItem(item.get()));

    m_graph->layout();
    this->updateScrollBars();
    this->update();
}

GraphItem *GraphView::createItem(REDasm::Graphing::NodeData *data) { return new GraphItem(data, this); }

void GraphView::scrollContentsBy(int dx, int dy)
{
    QWidget* viewport = this->viewport();

    viewport->move(viewport->x() + dx,
                   viewport->y() + dy);
}

void GraphView::paintEvent(QPaintEvent* e)
{
    Q_UNUSED(e)

    QPainter painter(this->viewport());
    painter.setRenderHint(QPainter::Antialiasing, true);
    painter.fillRect(this->viewport()->rect(), QColor("azure"));

    this->drawEdges(&painter);
    this->drawBlocks(&painter);
}

void GraphView::wheelEvent(QWheelEvent *e)
{
    if(e->modifiers() & Qt::ControlModifier)
        return;

    QAbstractScrollArea::wheelEvent(e);
}

void GraphView::resizeEvent(QResizeEvent *e)
{
    QAbstractScrollArea::resizeEvent(e);
    this->updateScrollBars();
}

void GraphView::mousePressEvent(QMouseEvent *e)
{
    QAbstractScrollArea::mousePressEvent(e);

    if(e->button() == Qt::LeftButton)
    {
        m_lastpos = e->pos();
        this->setCursor(QCursor(Qt::ClosedHandCursor));
    }
}

void GraphView::mouseReleaseEvent(QMouseEvent *e)
{
    QAbstractScrollArea::mouseReleaseEvent(e);
}

void GraphView::mouseMoveEvent(QMouseEvent *e)
{
    QAbstractScrollArea::mouseMoveEvent(e);

    if(e->buttons() & Qt::LeftButton)
    {
        int xdelta = m_lastpos.x() - e->x();
        int ydelta = m_lastpos.y() - e->y();

        this->horizontalScrollBar()->setValue(this->horizontalScrollBar()->value() + xdelta);
        this->verticalScrollBar()->setValue(this->verticalScrollBar()->value() + ydelta);

        m_lastpos = e->pos();
    }
}

void GraphView::updateScrollBars()
{
    this->horizontalScrollBar()->setMaximum(m_graph->width());
    this->verticalScrollBar()->setMaximum(m_graph->height());

    this->viewport()->resize(std::max(this->width(), static_cast<int>(m_graph->width())),
                             std::max(this->height(), static_cast<int>(m_graph->height())));
}

void GraphView::drawBlocks(QPainter *painter)
{
    for(GraphItem* gi : m_items)
    {
        painter->fillRect(gi->boundingRect().adjusted(DROP_SHADOW_ARG), Qt::lightGray);
        gi->paint(painter);
    }
}

void GraphView::drawEdges(QPainter *painter)
{
    for(ogdf::EdgeElement* edge : m_graph->edges())
        this->drawEdge(painter, edge);
}

void GraphView::drawEdge(QPainter* painter, ogdf::EdgeElement* edge)
{
    const ogdf::DPolyline& polyline = m_graph->polyline(edge);
    QVector<QPointF> lines;

    for(const ogdf::DPoint& p : polyline)
        lines.push_front(QPointF(p.m_x, p.m_y));

    painter->setPen(QPen(Qt::black, 2));
    painter->drawPolyline(lines.data(), lines.size());
}
