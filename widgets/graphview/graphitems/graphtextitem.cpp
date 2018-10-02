#include "graphtextitem.h"
#include "../graphmetrics.h"
#include <QApplication>
#include <QPalette>
#include <cmath>

GraphTextItem::GraphTextItem(REDasm::Graphing::NodeData *data, QObject *parent) : GraphRectItem(data, parent) { }

void GraphTextItem::paint(QPainter *painter)
{
    QRectF r = this->boundingRect();
    int p = GraphMetrics::borderPadding();
    painter->fillRect(r.adjusted(-p, -p, p, p), qApp->palette().brush(QPalette::Base));

    painter->save();
        painter->translate(r.topLeft());
        m_textdocument.drawContents(painter);
    painter->restore();

    GraphRectItem::paint(painter);
}
