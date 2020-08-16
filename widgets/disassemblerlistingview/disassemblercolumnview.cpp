#include "disassemblercolumnview.h"
#include "../../themeprovider.h"
#include "disassemblertextview.h"
#include <QScrollBar>
#include <QPainter>
#include <QPainterPath>

DisassemblerColumnView::DisassemblerColumnView(QWidget *parent): QWidget(parent)
{
    this->setBackgroundRole(QPalette::Base);
    this->setAutoFillBackground(true);

    RDEvent_Subscribe(this, [](const RDEventArgs* e) {
        auto* thethis = reinterpret_cast<DisassemblerColumnView*>(e->owner);
        if(!thethis->m_disassembler || RD_IsBusy()) return;

        if(e->eventid == Event_BusyChanged) QMetaObject::invokeMethod(thethis, "renderArrows", Qt::QueuedConnection);
        else if(e->eventid == Event_CursorPositionChanged) QMetaObject::invokeMethod(thethis, "update", Qt::QueuedConnection);
    }, nullptr);
}

DisassemblerColumnView::~DisassemblerColumnView() { RDEvent_Unsubscribe(this); }

void DisassemblerColumnView::linkTo(DisassemblerTextView* textview)
{
    m_textview = textview;
    m_disassembler = textview->disassembler();
    m_document = RDDisassembler_GetDocument(m_disassembler);

    connect(m_textview->verticalScrollBar(), &QScrollBar::valueChanged, this, [&](int) { this->renderArrows(); });
}

void DisassemblerColumnView::renderArrows(size_t start, size_t count)
{
    m_first = start;
    m_last = start + count - 1;

    m_paths.clear();
    m_done.clear();

    if(RD_IsBusy()) return;

    const RDNet* net = RDDisassembler_GetNet(m_disassembler);

    for(size_t i = 0; i < count; i++, start++)
    {
        if(start >= RDDocument_ItemsCount(m_document)) break;

        RDDocumentItem item;
        if(!RDDocument_GetItemAt(m_document, start, &item)) continue;

        if(IS_TYPE(&item, DocumentItemType_Instruction))
        {
            const RDNetNode* node = RDNet_FindNode(net, item.address);
            if(!node) continue;

            const rd_address* branches = nullptr;
            size_t c = RDNetNode_GetBranchesTrue(node, &branches);

            for(size_t i = 0; i < c; i++)
            {
                rd_address branch = branches[i];
                if(branch == item.address) continue;

                size_t idx = RDDocument_InstructionIndex(m_document, branch);
                if(idx >= RDDocument_ItemsCount(m_document)) continue;
                this->insertPath(net, item, start, idx);
            }
        }
        else if(IS_TYPE(&item, DocumentItemType_Symbol))
        {
            RDSymbol symbol;
            if(!RDDocument_GetSymbolByAddress(m_document, item.address, &symbol) || !IS_TYPE(&symbol, SymbolType_Label)) continue;

            size_t toidx = RDDocument_InstructionIndex(m_document, item.address);
            if(toidx >= RDDocument_ItemsCount(m_document)) continue;

            const rd_address* refs = nullptr;
            size_t c = RDNet_GetRefs(net, item.address, &refs);

            for(size_t i = 0; i < c; i++)
            {
                rd_address r = refs[i];
                if(r == item.address) continue;

                size_t idx = RDDocument_InstructionIndex(m_document, r);
                if(idx >= RDDocument_ItemsCount(m_document)) continue;

                RDDocumentItem item;
                RDDocument_GetItemAt(m_document, idx, &item);
                this->insertPath(net, item, idx, toidx);
            }
        }
    }

    std::sort(m_paths.begin(), m_paths.end(), [](const ArrowPath& p1, const ArrowPath& p2) -> bool {
        return p1.startidx < p2.startidx;
    });

    this->update();
}

void DisassemblerColumnView::renderArrows()
{
    if(RD_IsBusy() || !m_textview) return;
    this->renderArrows(m_textview->firstVisibleLine(), m_textview->visibleLines());
}

void DisassemblerColumnView::paintEvent(QPaintEvent*)
{
    if(!m_disassembler || m_paths.empty())
        return;

    QPainter painter(this);
    QFontMetrics fm = this->fontMetrics();

#if QT_VERSION >= QT_VERSION_CHECK(5, 11, 0)
    int w = fm.horizontalAdvance(" ");
#else
    int w = fm.width(" ");
#endif

    int h = fm.height(), x = this->width() - (w * 2);

    for(auto it = m_paths.begin(); it != m_paths.end(); it++, x -= w)
    {
        const ArrowPath& path = *it;
        int y1 = ((path.startidx - m_first) * h) + (h / 4);
        int y2 = ((path.endidx - m_first) * h) + ((h * 3) / 4);
        int y = ((path.endidx - m_first) * h);
        int penwidth = this->isPathSelected(path) ? 3 : 2;

        if(y2 > (y + (h / 2)))
            y2 -= penwidth;
        else if(y2 < (y + (h / 2)))
            y2 += penwidth;

        QVector<QLine> points;
        points.push_back(QLine(this->width(), y1, x, y1));
        points.push_back(QLine(x, y1, x, y2));
        points.push_back(QLine(x, y2, this->width(), y2));

        Qt::PenStyle penstyle = ((path.startidx < m_first) || (path.endidx > m_last)) ? Qt::DotLine : Qt::SolidLine;

        painter.setPen(QPen(path.color, penwidth, penstyle));
        painter.drawLines(points);

        painter.setPen(QPen(path.color, penwidth, Qt::SolidLine));
        this->fillArrow(&painter, y2, fm);
    }
}

bool DisassemblerColumnView::isPathSelected(const DisassemblerColumnView::ArrowPath &path) const
{
    size_t line = m_textview->currentPosition()->line;
    return (line == path.startidx) || (line == path.endidx);
}

void DisassemblerColumnView::fillArrow(QPainter* painter, int y, const QFontMetrics& fm)
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

void DisassemblerColumnView::insertPath(const RDNet* net, const RDDocumentItem& fromitem, size_t fromidx, size_t toidx)
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
