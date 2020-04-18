#include "painterrenderer.h"
#include "../redasmsettings.h"
#include "../themeprovider.h"
#include <algorithm>
#include <cstring>
#include <limits>
#include <cmath>
#include <QApplication>
#include <QPainter>
#include <QDebug>

PainterRenderer::PainterRenderer(RDDisassembler* disassembler, flag_t flags): m_fontmetrics(REDasmSettings::font())
{
    m_document = RDDisassembler_GetDocument(disassembler);
    m_cursor = RDCursor_Create(m_document);
    m_renderer = RDRenderer_Create(disassembler, m_cursor, flags);
}

PainterRenderer::~PainterRenderer()
{
    RD_Free(m_renderer);
    RD_Free(m_cursor);
}

QString PainterRenderer::currentWord() const { return RDRenderer_GetCurrentWord(m_renderer); }
QString PainterRenderer::selectedText() const { return RDRenderer_GetSelectedText(m_renderer); }
bool PainterRenderer::selectedSymbol(RDSymbol* symbol) const { return RDRenderer_GetSelectedSymbol(m_renderer, symbol); }
const QFontMetricsF PainterRenderer::fontMetrics() const { return m_fontmetrics; }
const RDRenderer* PainterRenderer::handle() const { return m_renderer; }
RDCursor* PainterRenderer::cursor() const { return m_cursor; }

void PainterRenderer::moveTo(const QPointF& p)
{
    RDCursorPos pos = this->hitTest(p);
    RDCursor_MoveTo(m_cursor, pos.line, pos.column);
}

void PainterRenderer::select(const QPointF& p)
{
    RDCursorPos pos = this->hitTest(p);
    RDCursor_Select(m_cursor, pos.line, pos.column);
}

RDCursorPos PainterRenderer::hitTest(const QPointF& p)
{
    RDCursorPos cp;
    cp.line = std::min(static_cast<size_t>(std::floor(p.y() / m_fontmetrics.height())), RDDocument_ItemsCount(m_document) - 1);
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

    if(cp.column == std::numeric_limits<size_t>::max())
        cp.column = static_cast<size_t>(std::max(0, s.size() - 1));

    return cp;
}

void PainterRenderer::render(QPainter* painter, size_t first, size_t last)
{
    m_painter = painter;
    size_t count = (last - first) + 1;

    RDRenderer_GetItems(m_renderer, first, count, [](const RDRendererItem* item, size_t index, void* userdata) {
        auto* thethis = reinterpret_cast<PainterRenderer*>(userdata);
        thethis->render(item, index);
    }, this);
}

void PainterRenderer::render(const RDRendererItem* item, size_t index)
{
    QFontMetrics fm = m_painter->fontMetrics();
    double x = 0, y = static_cast<double>(index) * fm.height();

    if(RDCursor_CurrentLine(m_cursor) == RDRendererItem_GetDocumentIndex(item))
    {
        QRect vpr = m_painter->viewport();
        m_painter->fillRect(0, static_cast<int>(y), vpr.width(), fm.height(), THEME_VALUE("seek"));
    }

    const RDRendererFormat* formats = nullptr;
    const char* text = RDRendererItem_GetItemText(item);
    size_t c = RDRendererItem_GetItemFormats(item, &formats);

    for(size_t i = 0; i < c; i++)
    {
        const RDRendererFormat& rf = formats[i];

        if(std::strlen(rf.fgstyle))
        {
            if(!std::strcmp(rf.fgstyle, "cursor_fg") || !std::strcmp(rf.fgstyle, "selection_fg"))
                m_painter->setPen(qApp->palette().color(QPalette::HighlightedText));
            else
                m_painter->setPen(THEME_VALUE(rf.fgstyle));
        }
        else
            m_painter->setPen(qApp->palette().color(QPalette::WindowText));

        QString chunk = QString::fromLocal8Bit(text + rf.start, static_cast<int>(rf.end - rf.start) + 1);

#if QT_VERSION >= QT_VERSION_CHECK(5, 11, 0)
        double w = fm.horizontalAdvance(chunk);
#else
        double w = fm.width(chunk);
#endif

        QRectF chunkrect = m_painter->boundingRect(QRectF(x, y, w, fm.height()), Qt::TextIncludeTrailingSpaces, chunk);

        if(std::strlen(rf.bgstyle))
        {
            if(!std::strcmp(rf.bgstyle, "cursor_bg"))
                m_painter->fillRect(chunkrect, qApp->palette().color(QPalette::WindowText));
            else if(!std::strcmp(rf.bgstyle, "selection_bg"))
                m_painter->fillRect(chunkrect, qApp->palette().color(QPalette::Highlight));
            else
                m_painter->fillRect(chunkrect, THEME_VALUE(rf.bgstyle));
        }

        m_painter->drawText(chunkrect, Qt::TextSingleLine, chunk);
        x += chunkrect.width();
    }
}
