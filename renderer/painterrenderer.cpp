#include "painterrenderer.h"
#include "../themeprovider.h"
#include <QApplication>
#include <QPainter>
#include <algorithm>
#include <cstring>

PainterRenderer::PainterRenderer(const RDContextPtr& disassembler, rd_flag flags, QObject* parent): QtRenderer(disassembler, nullptr, flags, parent) { }

void PainterRenderer::render(QPainter* painter, size_t first, size_t last)
{
    if(!m_renderer) return;

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
        m_painter->fillRect(0, static_cast<int>(y), vpr.width(), fm.height(), THEME_VALUE(Theme_Seek));
    }

    const RDRendererFormat* formats = nullptr;
    const char* text = RDRendererItem_GetItemText(item);
    size_t c = RDRendererItem_GetItemFormats(item, &formats);

    for(size_t i = 0; i < c; i++)
    {
        const RDRendererFormat& rf = formats[i];

        if(rf.fgtheme != Theme_Default)
        {
            if((rf.fgtheme == Theme_CursorFg) || (rf.fgtheme == Theme_SelectionFg))
                m_painter->setPen(qApp->palette().color(QPalette::HighlightedText));
            else
                m_painter->setPen(THEME_VALUE(rf.fgtheme));
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

        if(rf.bgtheme != Theme_Default)
        {
            if(rf.bgtheme == Theme_CursorBg)
                m_painter->fillRect(chunkrect, qApp->palette().color(QPalette::WindowText));
            else if(rf.bgtheme == Theme_SelectionBg)
                m_painter->fillRect(chunkrect, qApp->palette().color(QPalette::Highlight));
            else
                m_painter->fillRect(chunkrect, THEME_VALUE(rf.bgtheme));
        }

        m_painter->drawText(chunkrect, Qt::TextSingleLine, chunk);
        x += chunkrect.width();
    }
}
