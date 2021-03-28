#include "listingblockitem.h"
#include <QApplication>
#include <QPainter>
#include <QWidget>

#define DROP_SHADOW_SIZE  10

ListingBlockItem::ListingBlockItem(SurfaceQt* surface, const RDFunctionBasicBlock* fbb, RDGraphNode n, const RDGraph* g, QWidget *parent) : GraphViewItem(n, g, parent), m_basicblock(fbb), m_surface(surface) { }
bool ListingBlockItem::contains(rd_address address) const { return RDFunctionBasicBlock_Contains(m_basicblock, address); }

int ListingBlockItem::currentRow() const
{
    rd_address address = m_surface->currentAddress();

    if((address != RD_NVAL) && this->contains(address))
        return m_surface->position()->row - this->startRow();

    return GraphViewItem::currentRow();
}

QSize ListingBlockItem::size() const
{
    return m_surface->rangeSize(RDFunctionBasicBlock_GetStartAddress(m_basicblock),
                                RDFunctionBasicBlock_ItemsCount(m_basicblock));
}

void ListingBlockItem::itemSelectionChanged(bool selected) { m_surface->activateCursor(selected); }
void ListingBlockItem::mouseDoubleClickEvent(QMouseEvent*) { Q_EMIT followRequested(); }

void ListingBlockItem::mousePressEvent(QMouseEvent *e)
{
    if(e->buttons() == Qt::LeftButton)
    {
        int row, col;
        this->localPosToSurface(e->localPos(), &row, &col);
        m_surface->moveTo(row, col);
    }
    else GraphViewItem::mousePressEvent(e);

    e->accept();
}

void ListingBlockItem::mouseMoveEvent(QMouseEvent *e)
{
    if(e->buttons() != Qt::LeftButton) return;

    int row, col;
    this->localPosToSurface(e->localPos(), &row, &col);
    m_surface->select(row, col);
    e->accept();
}

void ListingBlockItem::localPosToSurface(const QPointF& pt, int* row, int* col) const
{
    *row = this->startRow() + (pt.y() / m_surface->cellHeight());
    *col = (pt.x() / m_surface->cellWidth());
}

int ListingBlockItem::startRow() const { return RDSurface_IndexOf(m_surface->handle(), RDFunctionBasicBlock_GetStartAddress(m_basicblock)); }

void ListingBlockItem::render(QPainter *painter, size_t)
{
    QRect r(QPoint(0, 0), this->size());
    r.adjust(BLOCK_MARGINS);

    QColor shadow = painter->pen().color();
    shadow.setAlpha(127);

    painter->save();
        painter->translate(this->position());
        painter->fillRect(r.adjusted(DROP_SHADOW_SIZE, DROP_SHADOW_SIZE, DROP_SHADOW_SIZE, DROP_SHADOW_SIZE), shadow);
        painter->fillRect(r, qApp->palette().color(QPalette::Base));

        if(m_surface)
        {
            painter->setClipRect(r);
            m_surface->renderRange(painter,
                                   RDFunctionBasicBlock_GetStartAddress(m_basicblock),
                                   RDFunctionBasicBlock_ItemsCount(m_basicblock));
        }

        painter->setPen(QPen(qApp->palette().color(QPalette::WindowText), 1.5));
        painter->drawRect(r);
    painter->restore();
}
