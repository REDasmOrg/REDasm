#include "graphitem.h"

GraphItem::GraphItem(REDasm::Graphing::Vertex *v, QObject *parent): QObject(parent), m_vertex(v) { }
REDasm::Graphing::Vertex *GraphItem::vertex() { return m_vertex; }
REDasm::Graphing::vertex_index_t GraphItem::index() const { return m_vertex->index(); }
REDasm::Graphing::vertex_layer_t GraphItem::layer() const { return m_vertex->layer(); }
REDasm::Graphing::vertex_id_t GraphItem::id() const { return m_vertex->id; }
bool GraphItem::isFake() const { return m_vertex->isFake(); }

void GraphItem::setPosition(int x, int y)
{
    m_pos.setX(x);
    m_pos.setY(y);
}

QRect GraphItem::boundingRect() const { return QRect(m_pos, QSize()); }
void GraphItem::paint(QPainter *painter) { Q_UNUSED(painter) }
