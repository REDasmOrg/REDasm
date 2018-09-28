#include "graphrectitem.h"
#include "../graphmetrics.h"

GraphRectItem::GraphRectItem(REDasm::Graphing::Vertex *v, QObject *parent): GraphItem(v, parent)
{

}

void GraphRectItem::paint(QPainter *painter)
{
    int p = GraphMetrics::borderPadding();

    painter->setPen(Qt::black);
    painter->drawRect(this->boundingRect().adjusted(-p, -p, p, p));
}
