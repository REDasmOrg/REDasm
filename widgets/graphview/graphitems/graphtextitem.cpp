#include "graphtextitem.h"
#include <QApplication>
#include <QPalette>
#include <cmath>

GraphTextItem::GraphTextItem(REDasm::Graphing::Vertex *v, QObject *parent) : GraphRectItem(v, parent) { }

QRect GraphTextItem::boundingRect() const
{
    QRect r = GraphRectItem::boundingRect();
    r.setSize(m_textdocument.size().toSize());
    return r;
}

void GraphTextItem::paint(QPainter *painter)
{
    QRect r = this->boundingRect();
    painter->fillRect(r, qApp->palette().brush(QPalette::Base));

    painter->save();
        painter->translate(r.topLeft());
        m_textdocument.drawContents(painter);
    painter->restore();

    GraphRectItem::paint(painter);
}
