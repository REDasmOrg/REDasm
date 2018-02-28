#include "graphitem.h"

GraphItem::GraphItem(REDasm::Graphing::Vertex *v, QObject *parent): QObject(parent), _vertex(v)
{

}

const REDasm::Graphing::Vertex *GraphItem::vertex() const
{
    return this->_vertex;
}

QColor GraphItem::borderColor() const
{
    return Qt::black;
}

QRect GraphItem::rect() const
{
    return QRect(this->position(), this->size());
}

const QPoint &GraphItem::position() const
{
    return this->_pos;
}

void GraphItem::move(int x, int y)
{
    this->_pos.setX(x);
    this->_pos.setY(y);
}
