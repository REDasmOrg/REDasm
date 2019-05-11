#include "graphview.h"
#include <QMouseEvent>
#include <QScrollBar>
#include <QPainter>
#include <QDebug>

GraphView::GraphView(QWidget *parent): QAbstractScrollArea(parent), m_disassembler(nullptr), m_selecteditem(nullptr)
{
    m_prevscalefactor = m_scaledirection = 0;
    m_scalemax = 5.0;
    m_scalefactor = m_scaleboost = 1.0;
    m_scalestep = 0.1;
    m_viewportready = false;
    m_scrollmode = true;
    m_scalemin = 0;

    QPalette palette = this->palette();
    palette.setColor(QPalette::Base, THEME_VALUE("graph_bg"));

    this->horizontalScrollBar()->setSingleStep(this->fontMetrics().height());
    this->verticalScrollBar()->setSingleStep(this->fontMetrics().height());
    this->setAutoFillBackground(true);
    this->setPalette(palette);
}

void GraphView::setDisassembler(const REDasm::DisassemblerPtr& disassembler) { m_disassembler = disassembler; }

void GraphView::setGraph(REDasm::Graphing::Graph *graph)
{
    m_selecteditem = nullptr;
    m_scalefactor = m_scaleboost = 1.0;
    qDeleteAll(m_items);
    m_items.clear();
    m_lines.clear();
    m_arrows.clear();

    m_graph = graph;
    this->computeLayout();
}

GraphViewItem *GraphView::selectedItem() const { return m_selecteditem; }
REDasm::Graphing::Graph *GraphView::graph() const { return m_graph; }

void GraphView::focusSelectedBlock()
{
    if(m_selecteditem)
        this->focusBlock(m_selecteditem);
}

void GraphView::focusBlock(const GraphViewItem *item, bool force)
{
    // Don't update the view for blocks that are already fully in view
    int xofs = this->horizontalScrollBar()->value();
    int yofs = this->verticalScrollBar()->value();
    QRect viewportrect = this->viewport()->rect();

    //before being shown for the first time viewport is kind of 98x28 so setting the parent size almost fixes this problem
    if(!m_viewportready)
        viewportrect.setSize(this->parentWidget()->size() - QSize(20, 20));

    QPoint translation(m_renderoffset.x() - xofs, m_renderoffset.y() - yofs);

    //Adjust scaled viewport
    viewportrect.setWidth(viewportrect.width() / m_scalefactor);
    viewportrect.setHeight(viewportrect.height() / m_scalefactor);
    viewportrect.translate(-translation.x() / m_scalefactor, -translation.y() / m_scalefactor);

    QFontMetrics fm = this->fontMetrics();
    QRect r(item->x() + fm.height(), item->width() + fm.height(),
            item->width() - (2 * fm.height()), item->height() - (2 * fm.height()));

    if(force || !viewportrect.contains(r))
    {
        auto x = (item->x() + static_cast<int>(item->width() / 2)) * m_scalefactor;
        auto y = (item->y() + (2 * fm.height()) + (item->currentLine() * fm.height())) * m_scalefactor;
        this->horizontalScrollBar()->setValue(x + m_renderoffset.x() - static_cast<int>(this->horizontalScrollBar()->pageStep() / 2));
        this->verticalScrollBar()->setValue(y + m_renderoffset.y() - static_cast<int>(this->verticalScrollBar()->pageStep() / 2));
    }
}

void GraphView::mouseDoubleClickEvent(QMouseEvent* e)
{
    bool updated = this->updateSelectedItem(e);

    if(m_selecteditem && (e->buttons() == Qt::LeftButton))
        m_selecteditem->mouseDoubleClickEvent(e);

    if(updated)
        this->selectedItemChangedEvent();

    QAbstractScrollArea::mouseDoubleClickEvent(e);
}

void GraphView::mousePressEvent(QMouseEvent *e)
{
    bool updated = this->updateSelectedItem(e);

    if(m_selecteditem)
        m_selecteditem->mousePressEvent(e);
    else if(e->button() == Qt::LeftButton)
    {
        m_scrollmode = true;
        m_scrollbase = e->pos();
        this->setCursor(Qt::ClosedHandCursor);
        this->viewport()->grabMouse();
    }

    this->viewport()->update();

    if(updated)
        this->selectedItemChangedEvent();

    QAbstractScrollArea::mousePressEvent(e);
}

void GraphView::mouseReleaseEvent(QMouseEvent *e)
{
    this->viewport()->update();

    if(e->button() == Qt::LeftButton && m_scrollmode)
    {
        m_scrollmode = false;
        this->setCursor(Qt::ArrowCursor);
        this->viewport()->releaseMouse();
    }

    QAbstractScrollArea::mouseReleaseEvent(e);
}

void GraphView::mouseMoveEvent(QMouseEvent *e)
{
    if(m_selecteditem)
    {
        GraphViewItem* item = this->itemFromMouseEvent(e);

        if(item == m_selecteditem)
            m_selecteditem->mouseMoveEvent(e);

        return;
    }

    if(m_scrollmode)
    {
        QPoint delta(m_scrollbase.x() - e->x(), m_scrollbase.y() - e->y());
        m_scrollbase = e->pos();

        this->horizontalScrollBar()->setValue(this->horizontalScrollBar()->value() + delta.x());
        this->verticalScrollBar()->setValue(this->verticalScrollBar()->value() + delta.y());
    }

    QAbstractScrollArea::mouseMoveEvent(e);
}

void GraphView::wheelEvent(QWheelEvent *e)
{
    if(e->modifiers() & Qt::ControlModifier)
    {
        m_scaleboost = e->modifiers() & Qt::ShiftModifier ? 2 : 1;

        if(e->delta() > 0)
        {
            m_scaledirection = 1;
            this->zoomIn(e->pos());
        }
        else if(e->delta() < 0)
        {
            m_scaledirection = -1;
            this->zoomOut(e->pos());
        }

        e->accept();
        return;
    }

    QAbstractScrollArea::wheelEvent(e);
}

void GraphView::resizeEvent(QResizeEvent *e) { this->adjustSize(e->size().width(), e->size().height()); }

void GraphView::paintEvent(QPaintEvent *e)
{
    QPoint translation = { m_renderoffset.x() - this->horizontalScrollBar()->value(),
                           m_renderoffset.y() - this->verticalScrollBar()->value() };

    QPainter painter(this->viewport());
    painter.translate(translation);
    painter.scale(m_scalefactor, m_scalefactor);

    QRect vpr(this->viewport()->rect().topLeft(), this->viewport()->rect().bottomRight() - QPoint(1, 1));

    // Adjust imaginary viewport rect at new zoom level
    vpr.setWidth(vpr.width() / m_scalefactor);
    vpr.setHeight(vpr.height() / m_scalefactor);
    vpr.translate(-translation.x() / m_scalefactor, -translation.y() / m_scalefactor);

    // Render edges
    painter.save();

    for(auto it = m_lines.begin(); it != m_lines.end(); it++)
    {
        QColor c(QString::fromStdString(m_graph->color(it->first)));
        QPen pen(c);

        if(m_selecteditem && ((it->first.source == m_selecteditem->node()) || (it->first.target == m_selecteditem->node())))
        {
            pen.setWidthF(2.0 / m_scalefactor);
        }
        else
        {
            pen.setWidthF(1.0 / m_scalefactor);
            pen.setStyle(m_selecteditem ? Qt::DashLine : Qt::SolidLine);
        }

        painter.setPen(pen);
        painter.setBrush(c);
        painter.drawLines(it->second);

        pen.setStyle(Qt::SolidLine);
        painter.setPen(pen);
        painter.drawConvexPolygon(m_arrows[it->first]);
    }

    painter.restore();

    // Render nodes
    for(auto* item : m_items)
    {
        if(!vpr.intersects(item->rect())) // Ignore blocks that are not in view
            continue;

        size_t itemstate = GraphViewItem::None;

        if(m_selecteditem == item)
            itemstate |= GraphViewItem::Selected;

        item->render(&painter, itemstate);
    }
}

void GraphView::showEvent(QShowEvent *e)
{
    if(!m_viewportready)
        m_viewportready = true;

    e->ignore();
}

void GraphView::selectedItemChangedEvent()
{
    this->focusSelectedBlock();
    emit selectedItemChanged();
}

void GraphView::computeLayout()
{
    for(const auto& n : m_graph->nodes())
    {
        m_items[n]->move(QPoint(m_graph->x(n), m_graph->y(n)));
        connect(m_items[n], &GraphViewItem::invalidated, this->viewport(), [&]() { this->viewport()->update(); });
    }

    for(const auto& e : m_graph->edges())
    {
        this->precomputeLine(e);
        this->precomputeArrow(e);
    }

    QSize areasize;

    if(m_viewportready)
        areasize = this->viewport()->size();
    else
        areasize = this->parentWidget()->size() - QSize(20, 20);

    qreal sx = static_cast<qreal>(areasize.width()) / static_cast<qreal>(this->width());
    qreal sy = static_cast<qreal>(areasize.height()) / static_cast<qreal>(this->height());
    m_scalemin = std::min(static_cast<qreal>(std::min(sx, sy) * (1 - m_scalestep)), 0.05); // If graph is very large...

    this->adjustSize(areasize.width(), areasize.height());
    this->viewport()->update();
}

GraphViewItem *GraphView::itemFromMouseEvent(QMouseEvent *e) const
{
    //Convert coordinates to system used in blocks
    int xofs = this->horizontalScrollBar()->value();
    int yofs = this->verticalScrollBar()->value();

    QPoint pos = { static_cast<int>(std::floor((e->x() + xofs - m_renderoffset.x()) / m_scalefactor)),
                   static_cast<int>(std::floor((e->y() + yofs - m_renderoffset.y()) / m_scalefactor)) };

    for(GraphViewItem* item : m_items)
    {
        if(!item->contains(pos))
            continue;

        e->setLocalPos(item->mapToItem(pos));
        return item;
    }

    return nullptr;
}

void GraphView::zoomOut(const QPoint &cursorpos)
{
    m_prevscalefactor = m_scalefactor;

    if(m_scalefactor <= m_scalemin)
        return;

    m_scalefactor *= (1 - m_scalestep * m_scaleboost);

    if(m_scalefactor < m_scalemin)
        m_scalefactor = m_scalemin;

    QSize vpsize = this->viewport()->size();
    this->adjustSize(vpsize.width(), vpsize.height(), cursorpos);
    this->viewport()->update();
}

void GraphView::zoomIn(const QPoint &cursorpos)
{
    m_prevscalefactor = m_scalefactor;

    if(m_scalefactor >= m_scalemax)
        return;

    m_scalefactor /= (1 - m_scalestep * m_scaleboost);

    if(m_scalefactor > m_scalemax)
        m_scalefactor = m_scalemax;

    QSize vpsize = this->viewport()->size();
    this->adjustSize(vpsize.width(), vpsize.height(), cursorpos);
    this->viewport()->update();
}

void GraphView::adjustSize(int vpw, int vph, const QPoint &cursorpos, bool fit)
{
    //bugfix - resize event (during several initial calls) may reset correct adjustment already made
    if(vph < 30)
        return;

    m_rendersize = QSize(m_graph->areaWidth() * m_scalefactor, m_graph->areaHeight() * m_scalefactor);
    m_renderoffset = QPoint(vpw, vph);

    QSize scrollrange = { m_rendersize.width() + vpw, m_rendersize.height() + vph };
    qreal scalestepreal = 0.0;

    if(m_scaledirection > 0)
    {
        scalestepreal = (m_scalefactor - m_prevscalefactor) / m_scalefactor;
        scalestepreal /= (1 - scalestepreal);
    }
    else
        scalestepreal = (m_prevscalefactor - m_scalefactor) / m_prevscalefactor;

    QPoint deltaoffset(m_renderoffset.x() * scalestepreal * m_scaledirection, m_renderoffset.y() * scalestepreal * m_scaledirection);
    QPoint oldscrollpos(this->horizontalScrollBar()->value(), this->verticalScrollBar()->value());

    this->horizontalScrollBar()->setPageStep(vpw);
    this->horizontalScrollBar()->setRange(0, scrollrange.width());
    this->verticalScrollBar()->setPageStep(vph);
    this->verticalScrollBar()->setRange(0, scrollrange.height());

    if(!cursorpos.isNull())
    {
        QPointF deltacursorreal = cursorpos / m_prevscalefactor + oldscrollpos / m_prevscalefactor;
        QPointF deltacursordiff = deltacursorreal * m_scalefactor - deltacursorreal * m_prevscalefactor;

        this->horizontalScrollBar()->setValue(qRound(oldscrollpos.x() + deltacursordiff.x() - deltaoffset.x()));
        this->verticalScrollBar()->setValue(qRound(oldscrollpos.y() + deltacursordiff.y() - deltaoffset.y()));
    }
    else if(fit)
    {
        this->horizontalScrollBar()->setValue(scrollrange.width() / 2);
        this->verticalScrollBar()->setValue(scrollrange.height() / 2);
    }
}

void GraphView::precomputeArrow(const REDasm::Graphing::Edge &e)
{
    const REDasm::Graphing::Polyline& path = m_graph->arrow(e);
    QPolygon arrowhead;

    for(int i = 0; i < path.size(); i++)
    {
        const REDasm::Graphing::Point& p1 = path[i];
        arrowhead << QPoint(p1.x, p1.y);
    }

    m_arrows[e] = arrowhead;
}

void GraphView::precomputeLine(const REDasm::Graphing::Edge &e)
{
    const REDasm::Graphing::Polyline& path = m_graph->routes(e);

    QVector<QLine> lines;

    for(size_t i = 0; !path.empty() && (i < path.size() - 1); i++)
    {
        const REDasm::Graphing::Point& p1 = path[i];
        const REDasm::Graphing::Point& p2 = path[i + 1];
        lines.push_back(QLine(p1.x, p1.y, p2.x, p2.y));
    }

    m_lines[e] = lines;
}

bool GraphView::updateSelectedItem(QMouseEvent *e)
{
    GraphViewItem* olditem = m_selecteditem;
    m_selecteditem = this->itemFromMouseEvent(e);

    if(olditem)
    {
        olditem->itemSelectionChanged(false);
        olditem->invalidate();
     }

    if(m_selecteditem)
        m_selecteditem->itemSelectionChanged(false);

    return olditem != m_selecteditem;
}
