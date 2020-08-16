#include "rdilelementitem.h"

RDILElementItem::RDILElementItem(RDGraphNode node, const RDGraph* g, QObject* parent) : GraphViewItem(node, g, parent) { }

void RDILElementItem::render(QPainter* painter, size_t state)
{
    auto* data = RDGraph_GetData(this->graph(), this->node());
    QRect r(this->position(), this->size());
    painter->drawRect(r);

    if(data) painter->drawText(r, Qt::AlignCenter, data->s_data);
}

QSize RDILElementItem::size() const { return QSize(150, 32); }
