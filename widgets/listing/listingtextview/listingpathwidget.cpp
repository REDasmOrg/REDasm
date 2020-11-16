#include "listingpathwidget.h"
#include "../../../themeprovider.h"
#include "listingtextview.h"
#include <QScrollBar>
#include <QPainter>
#include <QPainterPath>

ListingPathWidget::ListingPathWidget(QWidget *parent): QWidget(parent)
{
    this->setBackgroundRole(QPalette::Base);
    this->setAutoFillBackground(true);
}

ListingPathWidget::~ListingPathWidget() { if(m_textview) RDObject_Unsubscribe(m_textview->surface()->handle(), this); }

void ListingPathWidget::linkTo(ListingTextWidget* textview)
{
    m_textview = textview;
    m_context = textview->context();
    m_document = RDContext_GetDocument(m_context.get());

    RDObject_Subscribe(textview->surface()->handle(), this, [](const RDEventArgs* e) {
        auto* thethis = reinterpret_cast<ListingPathWidget*>(e->owner);
        if(e->id != Event_SurfaceUpdated) return;
        QMetaObject::invokeMethod(thethis, "update", Qt::QueuedConnection);
    }, nullptr);
}

void ListingPathWidget::paintEvent(QPaintEvent*)
{
    if(!m_context || !m_textview) return;

    const RDPathItem* path = nullptr;
    size_t c = RDSurface_GetPath(m_textview->surface()->handle(), &path);
    if(!c) return;

    QPainter painter(this);
    QFontMetrics fm = this->fontMetrics();

#if QT_VERSION >= QT_VERSION_CHECK(5, 11, 0)
    int w = fm.horizontalAdvance(" ");
#else
    int w = fm.width(" ");
#endif

    int rows = 0;
    RDSurface_GetSize(m_textview->surface()->handle(), &rows, nullptr);

    int h = fm.height(), x = this->width() - (w * 2);

    for(size_t i = 0; i < c; i++, x -= w, path++)
    {
        int y1 = (path->fromrow * h) + (h / 4);
        int y2 = (std::min(path->torow, rows + 1) * h) + ((h * 3) / 4);
        int y = (std::min(path->torow, rows + 1) * h);
        int penwidth = this->isPathSelected(path) ? 3 : 2;

        if(y2 > (y + (h / 2))) y2 -= penwidth;
        else if(y2 < (y + (h / 2))) y2 += penwidth;

        QVector<QLine> points;
        points.push_back(QLine(this->width(), y1, x, y1));
        points.push_back(QLine(x, y1, x, y2));
        points.push_back(QLine(x, y2, this->width(), y2));

        Qt::PenStyle penstyle = ((path->fromrow == -1) || (path->torow > rows)) ? Qt::DotLine : Qt::SolidLine;
        painter.setPen(QPen(THEME_VALUE(path->style), penwidth, penstyle));
        painter.drawLines(points);

        painter.setPen(QPen(THEME_VALUE(path->style), penwidth, Qt::SolidLine));
        this->fillArrow(&painter, y2, fm);
    }
}

bool ListingPathWidget::isPathSelected(const RDPathItem* item) const
{
    int line = m_textview->surface()->position()->row;
    return (line == item->fromrow) || (line == item->torow);
}

void ListingPathWidget::fillArrow(QPainter* painter, int y, const QFontMetrics& fm)
{
#if QT_VERSION >= QT_VERSION_CHECK(5, 11, 0)
    int w = fm.horizontalAdvance(" ") / 2;
#else
    int w = fm.width(" ") / 2;
#endif

    int hl = fm.height() / 3;

    QPainterPath path;
    path.moveTo(QPoint(this->width() - w, y));
    path.lineTo(QPoint(this->width() - w, y - hl));
    path.lineTo(QPoint(this->width(), y));
    path.lineTo(QPoint(this->width() - w, y + hl));
    path.lineTo(QPoint(this->width() - w, y));

    painter->fillPath(path, painter->pen().brush());
}

void ListingPathWidget::insertPath(const RDNet* net, const RDDocumentItem& fromitem, size_t fromidx, size_t toidx)
{
    const RDNetNode* node = RDNet_FindNode(net, fromitem.address);
    if(!node) return;

    auto pair = qMakePair(fromidx, toidx);
    if(m_done.contains(pair)) return;

    m_done.insert(pair);

    if(fromidx > toidx) // Loop
    {
        if(RDNetNode_GetBranchesFalse(node, nullptr)) m_paths.append({ fromidx, toidx, THEME_VALUE(Theme_GraphEdgeLoopCond) });
        else m_paths.append({ fromidx, toidx, THEME_VALUE(Theme_GraphEdgeLoop) });
    }
    else
    {
        if(RDNetNode_GetBranchesFalse(node, nullptr)) m_paths.append({ fromidx, toidx, THEME_VALUE(Theme_GraphEdgeFalse) });
        else m_paths.append({ fromidx, toidx, THEME_VALUE(Theme_GraphEdge) });
    }
}
