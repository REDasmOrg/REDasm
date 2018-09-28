#include "graphview.h"
#include "graphmetrics.h"
#include <QtGui>

#define MINIMUM_SIZE 50

GraphView::GraphView(QWidget *parent): QAbstractScrollArea(parent)
{
    this->setFrameStyle(QFrame::StyledPanel | QFrame::Sunken);
}

void GraphView::setGraph(REDasm::Graphing::Graph* graph)
{
    m_graph = std::make_unique<REDasm::Graphing::Graph>(graph);
    m_lgraph = REDasm::Graphing::LayeredGraph(graph);

    s64 y = GraphMetrics::itemPadding(), maxx = 0;
    m_items.clear();

    for(REDasm::Graphing::VertexList& vl : m_lgraph)
    {
        s64 x = GraphMetrics::itemPadding(), maxheight = 0;

        for(REDasm::Graphing::Vertex* v : vl)
        {
            GraphItem* gi = this->createItem(v);
            gi->setPosition(x, y);

            QRect r = gi->boundingRect();
            x += r.width() + GraphMetrics::itemPadding();

            m_items[v->id] = gi;

            if(r.height() > maxheight)
                maxheight = r.height();
        }

        if(x > maxx)
            maxx = x;

        y += maxheight + this->getEdgesHeight(vl);
    }

    this->update();
}

GraphItem *GraphView::createItem(REDasm::Graphing::Vertex *v) { return new GraphItem(v, this); }

void GraphView::paintEvent(QPaintEvent* e)
{
    Q_UNUSED(e)

    QPainter painter(this->viewport());
    painter.setRenderHint(QPainter::Antialiasing, true);
    painter.fillRect(this->rect(), QColor("azure"));

    this->drawBlocks(&painter);
    this->drawEdges(&painter);
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
}

void GraphView::mousePressEvent(QMouseEvent *e)
{
    QAbstractScrollArea::mousePressEvent(e);

    /*
    if(e->button() == Qt::LeftButton)
    {
        m_lastpos = e->pos();
        this->setCursor(QCursor(Qt::ClosedHandCursor));
    }
    */
}

void GraphView::mouseReleaseEvent(QMouseEvent *e)
{
    QAbstractScrollArea::mouseReleaseEvent(e);
}

void GraphView::mouseMoveEvent(QMouseEvent *e)
{
    QAbstractScrollArea::mouseMoveEvent(e);

    /*
    if(e->buttons() & Qt::LeftButton)
    {
        int xdelta = m_lastpos.x() - e->x();
        int ydelta = m_lastpos.y() - e->y();

        this->horizontalScrollBar()->setValue(this->horizontalScrollBar()->value() + xdelta);
        this->verticalScrollBar()->setValue(this->verticalScrollBar()->value() + ydelta);

        m_lastpos = e->pos();
    }
    */
}

int GraphView::getEdgesHeight(const REDasm::Graphing::VertexList &vl) const
{
    size_t maxedges = 0;

    for(const REDasm::Graphing::Vertex* v : vl)
        maxedges = std::max(maxedges, v->edges.size());

    return (maxedges + 1) * GraphMetrics::itemPadding();
}

int GraphView::getEdgeIndex(GraphItem *from, GraphItem *to) const
{
    REDasm::Graphing::Vertex* vf = from->vertex();
    REDasm::Graphing::Vertex* vt = to->vertex();

    for(size_t i = 0; i < vf->edges.size(); i++)
    {
        if(vf->edges[i] == vt->id)
            return i;
    }

    return -1;
}

int GraphView::getLayerHeight(GraphItem *item) const
{
    int maxheight = 0;

    for(const REDasm::Graphing::Vertex* v : m_lgraph[item->layer()])
    {
        QRect rect = m_items[v->id]->boundingRect();
        maxheight = std::max(maxheight, rect.height());
    }

    return maxheight;
}

void GraphView::drawBlocks(QPainter *painter)
{
    for(GraphItem* gi : m_items)
    {
        if(gi->isFake())
            continue;

        gi->paint(painter);
    }
}

void GraphView::drawEdges(QPainter *painter)
{
    for(GraphItem* gi : m_items)
    {
        for(REDasm::Graphing::vertex_id_t vid : gi->vertex()->edges)
            this->drawEdge(painter, gi, m_items[vid]);
    }
}

void GraphView::drawEdge(QPainter* painter, GraphItem *from, GraphItem *to)
{
    QRect fr = from->boundingRect(), tr = to->boundingRect();
    QPoint fc = fr.center(), tc = tr.center();
    REDasm::Graphing::Vertex *rvf = m_graph->getRealParentVertex(from->vertex()), *rvt = m_graph->getRealVertex(to->vertex());
    int edgeheight = GraphMetrics::itemPadding() + (this->getEdgeIndex(from, to) * GraphMetrics::itemPadding());

    QVector<QPoint> lines;

    if(from->isFake())
    {
        int h = this->getLayerHeight(from);

        lines << QPoint(fc.x(), fr.bottom());
        lines << QPoint(fc.x(), fr.bottom() + h + edgeheight);
        lines << QPoint(tc.x(), fr.bottom() + h + edgeheight);
    }
    else
    {
        lines << QPoint(fc.x(), fr.bottom() + GraphMetrics::borderPadding());
        lines << QPoint(fc.x(), fr.bottom() + edgeheight);
        lines << QPoint(tc.x(), fr.bottom() + edgeheight);
    }

    if(to->isFake())
        lines << QPoint(tc.x(), tr.top());
    else
        lines << QPoint(tc.x(), tr.top() - GraphMetrics::borderPadding());

    QColor c(QString::fromStdString(rvf->edgeColor(rvt)));
    painter->setPen(QPen(c, 2));
    painter->drawPolyline(lines.data(), lines.size());
}
