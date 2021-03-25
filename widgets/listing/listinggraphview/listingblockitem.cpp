#include "listingblockitem.h"
#include <QApplication>
#include <QPainter>
#include <QWidget>

#define DROP_SHADOW_SIZE  10

ListingBlockItem::ListingBlockItem(const RDContextPtr& ctx, const RDFunctionBasicBlock* fbb, RDGraphNode n, const RDGraph* g, QWidget *parent) : GraphViewItem(n, g, parent), m_basicblock(fbb)
{
    m_surface = new SurfaceDocument(ctx, RendererFlags_Graph, parent);
    m_surface->setBaseColor(qApp->palette().color(QPalette::Base));

    connect(m_surface, &SurfaceDocument::renderCompleted, this, [&]() { this->invalidate(); }, Qt::QueuedConnection);
    m_surface->seek(RDFunctionBasicBlock_GetStartAddress(fbb));
    m_surface->resize(RDFunctionBasicBlock_ItemsCount(fbb), -1);
}

SurfaceQt* ListingBlockItem::surface() { return m_surface; }
bool ListingBlockItem::contains(rd_address address) const { return RDFunctionBasicBlock_Contains(m_basicblock, address); }

int ListingBlockItem::currentRow() const
{
    rd_address address = m_surface->currentAddress();

    if((address != RD_NVAL) && this->contains(address))
        return m_surface->position()->row;

    return GraphViewItem::currentRow();
}

QSize ListingBlockItem::size() const { return m_surface->size(); }
void ListingBlockItem::itemSelectionChanged(bool selected) { m_surface->activateCursor(selected); }
void ListingBlockItem::mouseDoubleClickEvent(QMouseEvent*) { Q_EMIT followRequested(); }

void ListingBlockItem::mousePressEvent(QMouseEvent *e)
{
    if(e->buttons() == Qt::LeftButton) m_surface->moveTo(e->localPos());
    else GraphViewItem::mousePressEvent(e);
    e->accept();
}

void ListingBlockItem::mouseMoveEvent(QMouseEvent *e)
{
    if(e->buttons() != Qt::LeftButton) return;
    e->accept();
    m_surface->select(e->localPos());
}

void ListingBlockItem::render(QPainter *painter, size_t state)
{
    QRect r(QPoint(0, 0), this->size());
    r.adjust(BLOCK_MARGINS);

    QColor shadow = painter->pen().color();
    shadow.setAlpha(127);

    painter->save();
        painter->translate(this->position());

        if(state & ListingBlockItem::Selected) // Thicker shadow
            painter->fillRect(r.adjusted(DROP_SHADOW_SIZE, DROP_SHADOW_SIZE, DROP_SHADOW_SIZE + 2, DROP_SHADOW_SIZE + 2), shadow);
        else
            painter->fillRect(r.adjusted(DROP_SHADOW_SIZE, DROP_SHADOW_SIZE, DROP_SHADOW_SIZE, DROP_SHADOW_SIZE), shadow);

        painter->fillRect(r, qApp->palette().color(QPalette::Base));
        if(m_surface) m_surface->renderTo(painter);

        if(state & ListingBlockItem::Selected)
            painter->setPen(QPen(qApp->palette().color(QPalette::Highlight), 2.0));
        else
            painter->setPen(QPen(qApp->palette().color(QPalette::WindowText), 1.5));

        painter->drawRect(r);
    painter->restore();
}
