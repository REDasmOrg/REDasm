#include "graphitem.h"

GraphItem::GraphItem(QObject *parent) : QObject(parent)
{

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
