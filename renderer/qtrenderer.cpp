#include "qtrenderer.h"
#include "../redasmsettings.h"
#include <QApplication>
#include <QClipboard>
#include <limits>
#include <cmath>
#include <iostream>

QtRenderer::QtRenderer(RDDisassembler* disassembler, RDCursor* cursor, rd_flag flags): m_fontmetrics(REDasmSettings::font())
{
    m_document = RDDisassembler_GetDocument(disassembler);

    if(cursor)
    {
        m_cursor = cursor;
        m_ownscursor = false;
    }
    else
        m_cursor = RDCursor_Create(m_document);

    m_renderer = RDRenderer_Create(disassembler, m_cursor, flags);
}

QtRenderer::~QtRenderer()
{
    RD_Free(m_renderer);
    if(m_ownscursor) RD_Free(m_cursor);
}

const QFontMetricsF& QtRenderer::fontMetrics() const { return m_fontmetrics; }
const RDRenderer* QtRenderer::handle() const { return m_renderer; }
RDCursor* QtRenderer::cursor() const { return m_cursor; }

RDCursorPos QtRenderer::hitTest(const QPointF& p, bool screen)
{
    RDCursorPos cp;
    cp.line = std::min(m_offset + static_cast<size_t>(std::floor(p.y() / m_fontmetrics.height())), RDDocument_ItemsCount(m_document) - 1);
    cp.column = std::numeric_limits<size_t>::max();

    rd_ptr<RDRendererItem> ritem(RDRender_CreateItem());
    if(!RDRenderer_GetItem(m_renderer, cp.line, ritem.get())) cp.column = 0;

    QString s = RDRendererItem_GetItemText(ritem.get());
    qreal x = 0;

    for(int i = 0; i < s.size(); i++)
    {
        qreal w = m_fontmetrics.width(s[i]);

        if(x >= p.x())
        {
            cp.column = static_cast<size_t>(std::max(0, i - 1));
            break;
        }

        x += w;
    }

    if(!screen && (cp.column == std::numeric_limits<size_t>::max()))
        cp.column = static_cast<size_t>(std::max(0, s.size() - 1));

    return cp;
}

QString QtRenderer::currentWord() const { return RDRenderer_GetCurrentWord(m_renderer); }
QString QtRenderer::selectedText() const { return RDRenderer_GetSelectedText(m_renderer); }

void QtRenderer::selectWordFromPoint(const QPointF& pt)
{
    RDCursorRange range;
    this->getWordFromPoint(pt, &range);
    if(range.start > range.end) return;

    size_t line = RDCursor_CurrentLine(m_cursor);
    RDCursor_MoveTo(m_cursor, line, range.start);
    RDCursor_Select(m_cursor, line, range.end);
}

void QtRenderer::setStartOffset(size_t offset) { m_offset = offset; }

QString QtRenderer::getWordFromPoint(const QPointF& pt, RDCursorRange* range)
{
    RDCursorPos pos = this->hitTest(pt, true);
    return RDRenderer_GetWordFromPosition(m_renderer, &pos, range);
}

bool QtRenderer::selectedSymbol(RDSymbol* symbol) const { return RDRenderer_GetSelectedSymbol(m_renderer, symbol); }

void QtRenderer::moveTo(const QPointF& p)
{
    RDCursorPos pos = this->hitTest(p);
    RDCursor_MoveTo(m_cursor, pos.line, pos.column);
}

void QtRenderer::select(const QPointF& p)
{
    RDCursorPos pos = this->hitTest(p);
    RDCursor_Select(m_cursor, pos.line, pos.column);
}

void QtRenderer::copy() const
{
    if(!RDCursor_HasSelection(m_cursor)) return;
    qApp->clipboard()->setText(this->selectedText());
}
