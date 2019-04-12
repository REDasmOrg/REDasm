#include "listingtextrenderer.h"
#include "listingrenderercommon.h"
#include "../themeprovider.h"
#include <cmath>
#include <QApplication>
#include <QTextCharFormat>
#include <QTextDocument>
#include <QPalette>
#include <QPainter>

ListingTextRenderer::ListingTextRenderer(const QFont &font, REDasm::DisassemblerAPI *disassembler): REDasm::ListingRenderer(disassembler), m_fontmetrics(font), m_firstline(0) { m_maxwidth = 0; }
int ListingTextRenderer::maxWidth() const { return static_cast<int>(m_maxwidth); }
void ListingTextRenderer::setFirstVisibleLine(u64 line) { m_firstline = line; }

REDasm::ListingCursor::Position ListingTextRenderer::hitTest(const QPointF &pos)
{
    REDasm::ListingCursor::Position cp;
    cp.first = std::min(static_cast<u64>(m_firstline + std::floor(pos.y() / m_fontmetrics.height())), m_document->lastLine());
    cp.second = std::numeric_limits<u64>::max();

    REDasm::RendererLine rl;

    if(!this->getRendererLine(cp.first, rl))
        cp.second = 0;

    std::string s = rl.text;
    qreal x = 0;

    for(size_t i = 0; i < s.length(); i++)
    {
        qreal w = m_fontmetrics.width(s[i]);

        if(x >= pos.x())
        {
            cp.second = i - 1;
            break;
        }

        x += w;
    }

    if(cp.second == std::numeric_limits<u64>::max())
        cp.second = static_cast<u64>(s.length() - 1);

    return cp;
}

std::string ListingTextRenderer::getWordFromPos(const QPointF &pos, REDasm::ListingRenderer::Range* wordpos)
{
    REDasm::ListingCursor::Position cp = this->hitTest(pos);
    return this->wordFromPosition(cp, wordpos);
}

REDasm::ListingRenderer::Range ListingTextRenderer::wordHitTest(const QPointF &pos)
{
    REDasm::ListingRenderer::Range wordpos;
    this->getWordFromPos(pos, &wordpos);
    return wordpos;
}

void ListingTextRenderer::renderLine(const REDasm::RendererLine &rl)
{
    if(rl.index > 0)
        m_maxwidth = std::max(m_maxwidth, m_fontmetrics.boundingRect(QString::fromStdString(rl.text)).width());
    else
        m_maxwidth = m_fontmetrics.boundingRect(QString::fromStdString(rl.text)).width();

    int y = (rl.documentindex - m_firstline) * m_fontmetrics.height();
    ListingRendererCommon::renderText(rl, 0, y, m_fontmetrics);
}
