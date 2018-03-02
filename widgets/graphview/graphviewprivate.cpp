#include "graphviewprivate.h"
#include <QGraphicsDropShadowEffect>
#include <QStack>
#include <cmath>

#define DROP_SHADOW_SIZE(x) x, x, x, x
#define DROP_SHADOW_VALUE 8
#define DROP_SHADOW_ARG   DROP_SHADOW_SIZE(DROP_SHADOW_VALUE)
#define PI                3.14
#define ARROW_SIZE        8

GraphViewPrivate::GraphViewPrivate(QWidget *parent) : QWidget(parent), _overviewmode(false)
{
    QPalette p = this->palette();
    p.setColor(QPalette::Background, Qt::white);
    this->setAutoFillBackground(true);
    this->setPalette(p);

    this->_graphsize = QSize(0, 0);
}

const QSize &GraphViewPrivate::graphSize() const
{
    return this->_graphsize;
}

void GraphViewPrivate::addItem(GraphItem *item)
{
    item->setParent(this); // Take ownership

    this->_items << item;
    this->_itembyid[item->vertex()->id] = item;
}

void GraphViewPrivate::removeAll()
{
    this->_graphsize = QSize(0, 0);

    if(!this->_items.isEmpty())
    {
        qDeleteAll(this->_items);
        this->_items.clear();
    }

    this->update();
}

bool GraphViewPrivate::overviewMode() const
{
    return this->_overviewmode;
}

void GraphViewPrivate::setOverviewMode(bool b)
{
    this->_overviewmode = b;
}

void GraphViewPrivate::drawArrow(QPainter *painter, GraphItem *fromitem, GraphItem *toitem)
{
    QRect fromrect = fromitem->rect(), torect = toitem->rect();
    QPoint fromcenter = fromrect.center(), tocenter = torect.center();
    QLineF line(tocenter.x(), torect.top() - 1, fromcenter.x(), fromrect.bottom() + 1);
    double angle = ::atan2(-line.dy(), line.dx());

    if(line.dy() > 0)
        angle = (PI / 2) - angle;

    QPointF p1 = line.p1() + QPointF(::sin(angle + PI / 3) * ARROW_SIZE,
                                     ::cos(angle + PI / 3) * ARROW_SIZE);

    QPointF p2 = line.p1() + QPointF(::sin(angle + PI - PI / 3) * ARROW_SIZE,
                                     ::cos(angle + PI - PI / 3) * ARROW_SIZE);


    painter->save();

        painter->setPen(QPen(toitem->borderColor(), 2));
        painter->setBrush(toitem->borderColor());
        painter->drawLine(line);

        if(!toitem->vertex()->isFake())
        {
            QPolygonF arrowhead;
            arrowhead << line.p1() << p1 << p2;
            painter->drawPolygon(arrowhead);
        }

    painter->restore();
}

void GraphViewPrivate::drawEdges(QPainter *painter, GraphItem* item)
{
    const REDasm::Graphing::Vertex* v = item->vertex();

    for(REDasm::Graphing::vertex_id_t edge : v->edges)
    {
        if(!this->_itembyid.contains(edge))
            continue;

        this->drawArrow(painter, item, this->_itembyid[edge]);
    }
}

void GraphViewPrivate::setGraphSize(const QSize &size)
{
    this->_graphsize = size;

    emit graphChanged();
    this->update();
}

void GraphViewPrivate::paintEvent(QPaintEvent*)
{
    QPainter painter(this);
    painter.setRenderHint(QPainter::Antialiasing);
    painter.eraseRect(this->rect());

    foreach(GraphItem* item, this->_items)
    {
        if(!item->vertex()->isFake())
        {
            painter.fillRect(item->rect().adjusted(DROP_SHADOW_ARG), Qt::lightGray);
            painter.fillRect(item->rect(), painter.background());

            painter.save();
            painter.setClipRect(item->rect().adjusted(-1, -1, 1, 1));
            item->paint(&painter);

            painter.setPen(QPen(item->borderColor(), 2));
            painter.drawRect(item->rect());
            painter.restore();
        }

        this->drawEdges(&painter, item);
    }
}
