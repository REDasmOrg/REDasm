#include "graphitem.h"

GraphItem::GraphItem(REDasm::Graphing::NodeData *data, QObject *parent): QObject(parent), m_data(data) { }
QRectF GraphItem::boundingRect() const { return QRectF(m_data->x(), m_data->y(), m_data->width(), m_data->height()); }
void GraphItem::paint(QPainter *painter) { Q_UNUSED(painter) }
