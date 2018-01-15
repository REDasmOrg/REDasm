#include "graphviewprivate.h"
#include <QDebug>
#include <QStack>
#include <cmath>

#define PI           3.14
#define ITEM_PADDING 15
#define ARROW_SIZE   8

GraphViewPrivate::GraphViewPrivate(QWidget *parent) : QWidget(parent), _overviewmode(false), _locklayout(false), _rootitem(NULL)
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

GraphItem* GraphViewPrivate::addRoot(GraphItem *item)
{
    this->_rootitem = item;

    this->addItem(item, true);
    return item;
}

void GraphViewPrivate::addEdge(GraphItem *fromitem, GraphItem *toitem)
{
    this->addItem(fromitem, false);
    this->addItem(toitem, false);

    this->_graph[fromitem] << toitem;
    this->layoutRoot();
}

void GraphViewPrivate::removeAll()
{
    this->_rootitem = NULL;
    this->_graphsize = QSize(0, 0);
    this->_processed.clear();
    this->_graph.clear();

    if(!this->_items.isEmpty())
    {
        qDeleteAll(this->_items);
        this->_items.clear();
    }

    this->update();
}

void GraphViewPrivate::beginInsertion()
{
    this->_locklayout = true;
}

void GraphViewPrivate::endInsertion()
{
    if(!this->_locklayout)
        return;

    this->_locklayout = false;
    this->layoutRoot();
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

    QPolygonF arrowhead;
    arrowhead << line.p1() << p1 << p2;

    painter->save();
        painter->setPen(toitem->borderColor());
        painter->setBrush(toitem->borderColor());
        painter->drawLine(line);
        painter->drawPolygon(arrowhead);
    painter->restore();
}

void GraphViewPrivate::drawEdges(QPainter *painter, GraphItem *item)
{
    const GraphItemList& itemlist = this->_graph[item];

    foreach(GraphItem* childitem, itemlist)
        this->drawArrow(painter, item, childitem);
}

void GraphViewPrivate::layoutRoot()
{
    if(!this->_rootitem)
        return;

    this->_processed.clear();
    this->_processed << this->_rootitem;

    QPoint center = this->parentWidget()->rect().center();
    QSize itemsize = this->_rootitem->size();
    this->_rootitem->move(center.x() - (itemsize.width() / 2), ITEM_PADDING);
    this->layoutEdges(this->_rootitem);

    this->_graphsize += itemsize;
    this->_processed.clear();
    this->update();

    emit graphDrawed();
}

QSize GraphViewPrivate::layoutEdges(GraphItem *parentitem)
{
    const GraphItemList& itemlist = this->_graph[parentitem];
    QRect parentrect = parentitem->rect();
    QPoint center = parentrect.center();
    QSize edgessize = this->edgesSize(parentitem);
    int y = parentrect.bottom() + ITEM_PADDING, x = center.x() - (edgessize.width() / 2);

    if(x <= 0)
        x = ITEM_PADDING;

    foreach(GraphItem* item, itemlist)
    {
        QSize childedgessize;

        if(!this->_processed.contains(item))
        {
            this->_processed << item;
            item->move(x, y);

            this->_graphsize += item->size();
            childedgessize = this->layoutEdges(item);
        }

        if(childedgessize.isEmpty())
            childedgessize = item->size();

        x += childedgessize.width() + ITEM_PADDING;
    }

    return edgessize;
}

void GraphViewPrivate::addItem(GraphItem *item, bool dolayout)
{
    item->setParent(this); // Take ownership

    if(!this->_graph.contains(item))
    {
        this->_graphsize += item->size();
        this->_items << item;
        this->_graph[item] = GraphItemList();
    }

    if(!this->_locklayout && dolayout)
        this->layoutRoot();
}

QSize GraphViewPrivate::edgesSize(GraphItem *item) const
{
    int w = 0, h = 0;
    const GraphItemList& edgelist = this->_graph[item];

    foreach(GraphItem* edgeitem, edgelist)
    {
        QSize sz = edgeitem->size();
        w += sz.width();
        h = qMax(h, sz.height());

        if(edgeitem != edgelist.last())
            w += ITEM_PADDING;
    }

    return QSize(w, h);
}

void GraphViewPrivate::paintEvent(QPaintEvent*)
{
    QPainter painter(this);
    painter.setRenderHint(QPainter::Antialiasing);
    painter.eraseRect(this->rect());

    if(this->_graph.isEmpty() || this->_locklayout)
        return;

    GraphItemMapIterator it(this->_graph);

    while(it.hasNext())
    {
        it.next();
        GraphItem* item = it.key();
        this->drawEdges(&painter, item);

        if(this->_processed.contains(item))
            continue;

        this->_processed << item;
        painter.save();
        painter.setClipRect(item->rect().adjusted(-1, -1, 1, 1));
        item->paint(&painter);

        painter.setPen(item->borderColor());
        painter.drawRect(item->rect());
        painter.restore();
    }

    this->_processed.clear();
}
