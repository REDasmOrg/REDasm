#include "graphviewitem.h"

GraphViewItem::GraphViewItem(RDGraphNode node, const RDGraph* g, QObject *parent): QObject(parent), m_node(node), m_graph(g) { }
const RDGraph* GraphViewItem::graph() const { return m_graph; }
RDGraphNode GraphViewItem::node() const { return m_node; }
int GraphViewItem::x() const { return this->position().x(); }
int GraphViewItem::y() const { return this->position().y(); }
int GraphViewItem::width() const { return this->size().width(); }
int GraphViewItem::height() const { return this->size().height(); }
QRect GraphViewItem::rect() const { return QRect(m_pos, this->size());  }
bool GraphViewItem::contains(const QPoint &p) const { return this->rect().contains(p); }
const QPoint &GraphViewItem::position() const { return m_pos; }
void GraphViewItem::move(const QPoint &pos) { m_pos = pos; }
void GraphViewItem::itemSelectionChanged(bool selected) { }
QPoint GraphViewItem::mapToItem(const QPoint &p) const { return QPoint(p.x() - m_pos.x(), p.y() - m_pos.y()); }
int GraphViewItem::currentRow() const { return 0; }
void GraphViewItem::mouseDoubleClickEvent(QMouseEvent *e) { }
void GraphViewItem::mousePressEvent(QMouseEvent* e) { }
void GraphViewItem::mouseMoveEvent(QMouseEvent *e) { }
void GraphViewItem::invalidate(bool notify) { if(notify) Q_EMIT invalidated(); }
