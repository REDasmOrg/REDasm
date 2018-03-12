#include "graphitem.h"

GraphItem::GraphItem(REDasm::Graphing::Vertex *v, QObject *parent): QObject(parent), _vertex(v)
{
    this->_defaultsize = QSize(0, 0);
}

const REDasm::Graphing::Vertex* GraphItem::vertex() const
{
    return this->_vertex;
}

REDasm::Graphing::vertex_layer_t GraphItem::layer() const
{
    return this->_vertex->layer();
}

bool GraphItem::isFake() const
{
    return this->_vertex->isFake();
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

void GraphItem::resize(int width, int height)
{
    this->_defaultsize = QSize(width, height);
}

QSize GraphItem::size() const
{
    return this->_defaultsize;
}

void GraphItem::paint(QPainter *painter)
{
    Q_UNUSED(painter);
}
