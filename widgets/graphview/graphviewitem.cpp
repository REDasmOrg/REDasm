#include "graphviewitem.h"

GraphViewItem::GraphViewItem(QObject *parent): QObject(parent) { }

int GraphViewItem::x() const { return this->position().x(); }
int GraphViewItem::y() const { return this->position().y(); }
int GraphViewItem::width() const { return this->size().width(); }
int GraphViewItem::height() const { return this->size().height(); }
QRect GraphViewItem::rect() const { return QRect(m_pos, this->size());  }
bool GraphViewItem::contains(const QPoint &p) const { return this->rect().contains(p); }
const QPoint &GraphViewItem::position() const { return m_pos; }
void GraphViewItem::move(const QPoint &pos) { m_pos = pos; }
QPoint GraphViewItem::mapToItem(const QPoint &p) const { return QPoint(p.x() - m_pos.x(), p.y() - m_pos.y()); }
