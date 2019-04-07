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
int ListingTextRenderer::lineHeight() const { return m_fontmetrics.height(); }
int ListingTextRenderer::maxWidth() const { return m_maxwidth; }
void ListingTextRenderer::setFirstVisibleLine(u64 line) { m_firstline = line; }

REDasm::ListingCursor::Position ListingTextRenderer::hitTest(const QPointF &pos, int firstline)
{
    REDasm::ListingCursor::Position cp;
    cp.first = std::min(static_cast<u64>(firstline + std::floor(pos.y() / m_fontmetrics.height())), m_document->lastLine());
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

std::string ListingTextRenderer::getWordUnderCursor(const QPointF &pos, int firstline, int *p)
{
    REDasm::ListingCursor::Position cp = this->hitTest(pos, firstline);
    return this->wordFromPosition(cp);
}

ListingTextRenderer::Range ListingTextRenderer::wordHitTest(const QPointF &pos, int firstline)
{
    int p = -1;
    std::string word = this->getWordUnderCursor(pos, firstline, &p);
    m_cursor->setWordUnderCursor(word);
    return std::make_pair(p, static_cast<int>(p + word.length() - 1));
}

void ListingTextRenderer::highlightWordUnderCursor() { m_cursor->setWordUnderCursor(this->wordFromPosition(m_cursor->currentPosition())); }

void ListingTextRenderer::renderLine(const REDasm::RendererLine &rl)
{
    if(rl.index > 0)
        m_maxwidth = std::max(m_maxwidth, m_fontmetrics.boundingRect(QString::fromStdString(rl.text)).width());
    else
        m_maxwidth = m_fontmetrics.boundingRect(QString::fromStdString(rl.text)).width();

    int y = (rl.documentindex - m_firstline) * m_fontmetrics.height();
    ListingRendererCommon::renderText(rl, 0, y, m_fontmetrics);
}
