#include "listingblockitem.h"
#include <QApplication>
#include <QPainter>
#include <QWidget>

#define BLOCK_MARGIN      4
#define DROP_SHADOW_SIZE  10
#define BLOCK_MARGINS     -BLOCK_MARGIN, 0, BLOCK_MARGIN, 0

ListingBlockItem::ListingBlockItem(const RDContextPtr& ctx, const RDFunctionBasicBlock* fbb, RDGraphNode n, const RDGraph* g, QWidget *parent) : GraphViewItem(n, g, parent), m_basicblock(fbb)
{
    m_surface = new SurfaceDocument(ctx, RendererFlags_NoSegment | RendererFlags_NoSeparators | RendererFlags_NoIndent, parent);
    m_surface->setBaseColor(qApp->palette().color(QPalette::Base));

    connect(m_surface, &SurfaceDocument::renderCompleted, this, [&]() { this->invalidate(); }, Qt::QueuedConnection);

    RDDocumentItem item;
    if(!RDFunctionBasicBlock_GetStartItem(fbb, &item)) return;

    m_surface->goTo(&item);
    m_surface->resize(RDFunctionBasicBlock_ItemsCount(fbb), -1);
}

SurfaceQt* ListingBlockItem::surface() { return m_surface; }
bool ListingBlockItem::containsItem(const RDDocumentItem& item) const { return RDFunctionBasicBlock_Contains(m_basicblock, item.address); }

int ListingBlockItem::currentRow() const
{
    // RDDocumentItem item;

    // if(m_surface->getCurrentItem(&item) && this->containsItem(item))
    //     return m_surface->position()->row;

    // return GraphViewItem::currentRow();
    return 0;
}

QSize ListingBlockItem::size() const { return m_surface->size(); }
void ListingBlockItem::itemSelectionChanged(bool selected) { m_surface->activateCursor(selected); }
void ListingBlockItem::mouseDoubleClickEvent(QMouseEvent*) { emit followRequested(); }

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
