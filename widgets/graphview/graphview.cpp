#include "graphview.h"
#include <QMouseEvent>
#include <QScrollBar>
#include <QPainter>

GraphView::GraphView(QWidget *parent): QAbstractScrollArea(parent), m_disassembler(NULL)
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

    this->setPalette(palette);
    this->setAutoFillBackground(true);
}

void GraphView::setDisassembler(REDasm::DisassemblerAPI *disassembler) { m_disassembler = disassembler; }

void GraphView::setGraph(REDasm::Graphing::Graph *graph)
{
    m_scalefactor = m_scaleboost = 1.0;
    qDeleteAll(m_items);
    m_items.clear();
    m_lines.clear();

    m_graph = std::unique_ptr<REDasm::Graphing::Graph>(graph);
    this->computeLayout();
}

REDasm::Graphing::Graph *GraphView::graph() const { return m_graph.get(); }

void GraphView::focusBlock(const GraphViewItem *item)
{
    int x = item->x() + m_renderoffset.x() + (item->width() / 2);
    int y = item->y() + m_renderoffset.y() + (item->height() / 2);
    this->horizontalScrollBar()->setValue(x - (this->width() / 2));
    this->verticalScrollBar()->setValue(y - (this->height() / 2));
}

void GraphView::mousePressEvent(QMouseEvent *e)
{
    if(e->button() == Qt::LeftButton)
    {
        m_scrollmode = true;
        m_scrollbase = e->pos();
        this->setCursor(Qt::ClosedHandCursor);
        this->viewport()->grabMouse();
    }

    QAbstractScrollArea::mousePressEvent(e);
}

void GraphView::mouseReleaseEvent(QMouseEvent *e)
{
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
    QPainter painter(this->viewport());
    painter.setRenderHint(QPainter::Antialiasing);

    painter.translate(m_renderoffset.x() - this->horizontalScrollBar()->value(),
                      m_renderoffset.y() - this->verticalScrollBar()->value());

    painter.scale(m_scalefactor, m_scalefactor);
    painter.save();

    for(auto it = m_lines.begin(); it != m_lines.end(); it++)
    {
        QColor c(QString::fromStdString(m_graph->color(it->first)));
        painter.setPen(QPen(c, 2.0));
        painter.setBrush(c);
        painter.drawLines(it->second);
        painter.drawConvexPolygon(m_arrows[it->first]);
    }

    painter.restore();

    for(auto* item : m_items)
        item->render(&painter);
}

void GraphView::showEvent(QShowEvent *e)
{
    if(!m_viewportready)
        m_viewportready = true;

    e->ignore();
}

void GraphView::computeLayout()
{
    for(const auto& n : m_graph->nodes())
        m_items[n]->move(QPoint(m_graph->x(n), m_graph->y(n)));

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

    float sx = static_cast<float>(areasize.width()) / static_cast<float>(this->width());
    float sy = static_cast<float>(areasize.height()) / static_cast<float>(this->height());
    m_scalemin = std::min(static_cast<double>(std::min(sx, sy) * (1 - m_scalestep)), 0.05); // if graph is very lagre

    this->adjustSize(areasize.width(), areasize.height());
    this->viewport()->update();
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
