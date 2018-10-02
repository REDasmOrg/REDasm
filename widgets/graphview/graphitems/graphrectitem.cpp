#include "graphrectitem.h"
#include "../graphmetrics.h"

GraphRectItem::GraphRectItem(REDasm::Graphing::NodeData *data, QObject *parent): GraphItem(data, parent)
{

}

void GraphRectItem::paint(QPainter *painter)
{
    int p = GraphMetrics::borderPadding();

    painter->setPen(Qt::black);
    painter->drawRect(this->boundingRect().adjusted(-p, -p, p, p));
}
