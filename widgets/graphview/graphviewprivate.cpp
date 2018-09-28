#include "graphviewprivate.h"
#include "graphmetrics.h"
#include <QWheelEvent>
#include <QStack>
#include <cmath>

#define DROP_SHADOW_SIZE(x) x, x, x, x
#define DROP_SHADOW_VALUE 8
#define DROP_SHADOW_ARG   DROP_SHADOW_SIZE(DROP_SHADOW_VALUE)
#define ZOOM_FACTOR_STEP  0.050
#define ITEM_PADDING      25

GraphViewPrivate::GraphViewPrivate(QWidget *parent) : QWidget(parent), m_overviewmode(false), m_zoomfactor(1.0), m_graph(NULL), m_lgraph(NULL)
{
    QPalette p = this->palette();
    p.setColor(QPalette::Background, QColor("azure"));
    this->setAutoFillBackground(true);
    this->setPalette(p);

    m_graphsize = QSize(0, 0);
}

const QSize &GraphViewPrivate::graphSize() const { return m_graphsize; }

void GraphViewPrivate::addItem(GraphItem *item)
{
    item->setParent(this); // Take ownership

    m_items << item;
    m_itembyid[item->vertex()->id] = item;
}

void GraphViewPrivate::removeAll()
{
    m_graphsize = QSize(0, 0);

    if(!m_items.isEmpty())
    {
        qDeleteAll(m_items);
        m_items.clear();
    }

    this->update();
}

bool GraphViewPrivate::overviewMode() const { return m_overviewmode; }
void GraphViewPrivate::setOverviewMode(bool b) { m_overviewmode = b; }

void GraphViewPrivate::setGraph(REDasm::Graphing::Graph *graph)
{
    m_graph = graph;
    //m_lgraph.setGraph(graph);
}

void GraphViewPrivate::drawEdge(QPainter *painter, GraphItem *fromitem, GraphItem *toitem, double offset)
{
    QRect fromrect = fromitem->boundingRect(), torect = toitem->boundingRect();
    QPoint fromcenter = fromrect.center(), tocenter = torect.center();
    double layerheight = this->getLayerHeight(fromitem);

    std::array<QPoint, 5> points;
    points[0] = QPoint(fromcenter.x() + offset, fromrect.bottom() + GraphMetrics::borderPadding());
    points[1] = QPoint(fromcenter.x() + offset, fromrect.top() + layerheight);
    points[2] = QPoint(fromcenter.x() + offset, fromrect.top() + layerheight + std::abs(offset) + GraphMetrics::angleSize());
    points[3] = QPoint(tocenter.x() + offset, fromrect.top() + layerheight + std::abs(offset) + GraphMetrics::angleSize());
    points[4] = QPoint(tocenter.x() + offset, tocenter.y() - GraphMetrics::borderPadding());
    painter->drawPolyline(points.data(), points.size());

    if(toitem->vertex()->isFake())
    {
        painter->drawLine(points[4], QPoint(tocenter.x() + offset, tocenter.y() + GraphMetrics::borderPadding()));
        return;
    }

    QPolygonF arrowhead;
    arrowhead << QPoint(points[4].x() - GraphMetrics::arrowSize(), torect.top() - (GraphMetrics::arrowSize() * 2))
              << QPoint(points[4].x() + GraphMetrics::arrowSize(), torect.top() - (GraphMetrics::arrowSize() * 2))
              << QPoint(points[4].x(), torect.top());

    painter->drawPolygon(arrowhead);
}

void GraphViewPrivate::drawEdges(QPainter *painter, GraphItem* item)
{
    const REDasm::Graphing::Vertex* v1 = item->vertex();
    painter->save();

    for(REDasm::Graphing::vertex_id_t edge : v1->edges)
    {
        if(!m_itembyid.contains(edge))
            continue;

        GraphItem* toitem = m_itembyid[edge];
        //REDasm::Graphing::Vertex *rv1 = m_graph->getRealParentVertex(v1->id), *rv2 = m_graph->getRealVertex(edge);
        //QColor c(QString::fromStdString(rv1->edgeColor(rv2)));

        //painter->setPen(QPen(c, 2));
        //painter->setBrush(c);
        //this->drawEdge(painter, item, toitem, this->getEdgeOffset(m_itembyid[rv1->id], toitem));
    }

    painter->restore();
}

void GraphViewPrivate::setGraphSize(const QSize &size)
{
    m_graphsize = size;

    emit graphChanged();
    this->update();
}

double GraphViewPrivate::getLayerHeight(GraphItem *item)
{
    if(!m_layerheight.contains(item->layer()))
    {
        double maxheight = 0;

        for(REDasm::Graphing::Vertex* v : m_lgraph[item->layer()])
        {
            GraphItem* litem = m_itembyid[v->id];
            //FIXME: maxheight = std::max(maxheight, static_cast<double>(litem->size().height()));
        }

        m_layerheight[item->layer()] = maxheight;
    }

    return m_layerheight[item->layer()];
}

double GraphViewPrivate::getEdgeOffset(GraphItem *fromitem, GraphItem *toitem) const
{
    const REDasm::Graphing::Vertex* fromvertex = fromitem->vertex();
    const REDasm::Graphing::EdgeList& edges = fromvertex->edges;
    double offset = fromitem->index() * GraphMetrics::edgeOffsetBase();

    if(edges.size() == 1)
        return offset;

    if(edges.size() == 2)
    {
        if(edges[0] == toitem->id())
            return offset + GraphMetrics::edgeOffsetBase();

        return offset + (GraphMetrics::edgeOffsetBase() * 2);
    }

    size_t mid = edges.size() / 2;

    for(size_t i = 0; i < edges.size(); i++)
    {
        if(edges[i] != toitem->id())
            continue;

        ssize_t offsetidx = i - static_cast<ssize_t>(mid);
        offset += GraphMetrics::edgeOffsetBase() * offsetidx;
        break;
    }

    return -offset;
}

void GraphViewPrivate::paintEvent(QPaintEvent*)
{
    if(!m_graph)
        return;

    m_layerheight.clear();

    QPainter painter(this);
    painter.setRenderHint(QPainter::Antialiasing);
    painter.eraseRect(this->rect());
    painter.scale(m_zoomfactor, m_zoomfactor);

    for(GraphItem* item : m_items)
    {
        if(!item->vertex()->isFake())
        {
            painter.fillRect(item->boundingRect().adjusted(DROP_SHADOW_ARG), Qt::lightGray);
            painter.fillRect(item->boundingRect(), QColor("white"));

            QRect cliprect = item->boundingRect().adjusted(-2, -2, 2, 2);
            painter.setClipRect(cliprect);

            painter.save();
                //FIXME: painter.translate(item->position());
                item->paint(&painter);
            painter.restore();

            //FIXME: painter.setPen(QPen(item->borderColor(), 1));
            painter.drawRect(cliprect);
        }

        this->drawEdges(&painter, item);
    }
}

void GraphViewPrivate::wheelEvent(QWheelEvent *event)
{
    QWidget::wheelEvent(event);

    if(event->modifiers() & Qt::ControlModifier)
    {
        if(event->delta() > 0)
            m_zoomfactor += ZOOM_FACTOR_STEP;
        else if(event->delta() < 0)
            m_zoomfactor -= ZOOM_FACTOR_STEP;
        else
            return;

        if(m_zoomfactor < 0.005)
            m_zoomfactor = 0.005;
        else if(m_zoomfactor > 2.005)
            m_zoomfactor = 2.005;

        this->update();
    }
}
