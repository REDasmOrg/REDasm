#include "listingtextrenderer.h"
#include "listingrenderercommon.h"
#include "../themeprovider.h"
#include <cmath>
#include <QApplication>
#include <QTextCharFormat>
#include <QTextDocument>
#include <QPalette>
#include <QPainter>

ListingTextRenderer::ListingTextRenderer(const QFont &font, REDasm::DisassemblerAPI *disassembler): REDasm::ListingRenderer(disassembler), m_font(font), m_fontmetrics(font), m_firstline(0), m_cursoractive(false)
{
    m_maxwidth = 0;
    m_rgxwords.setPattern(REDASM_WORD_REGEX);
    m_textoption.setWrapMode(QTextOption::NoWrap);
}

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

    for(size_t i = 0; i < s.length(); i++)
    {
        QRect r = m_fontmetrics.boundingRect(QString::fromStdString(s.substr(0, i + 1)));

        if(!r.contains(QPoint(pos.x(), r.y())))
            continue;

        cp.second = i;
        break;
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
bool ListingTextRenderer::cursorActive() const { return m_cursoractive; }
void ListingTextRenderer::toggleCursor() { m_cursoractive = !m_cursoractive; }
void ListingTextRenderer::enableCursor() { m_cursoractive = true; }
void ListingTextRenderer::disableCursor() { m_cursoractive = false; }

void ListingTextRenderer::renderLine(const REDasm::RendererLine &rl)
{
    QTextDocument textdocument;
    textdocument.setDocumentMargin(0);
    textdocument.setUndoRedoEnabled(false);
    textdocument.setDefaultTextOption(m_textoption);
    textdocument.setDefaultFont(m_font);

    QFontMetrics fm(textdocument.defaultFont());

    if(rl.index > 0)
        m_maxwidth = std::max(m_maxwidth, fm.boundingRect(QString::fromStdString(rl.text)).width());
    else
        m_maxwidth = fm.boundingRect(QString::fromStdString(rl.text)).width();

    ListingRendererCommon lrc(&textdocument, m_document);
    lrc.insertText(rl, m_cursoractive);

    QPainter* painter = reinterpret_cast<QPainter*>(rl.userdata);
    QRect rvp = painter->viewport();
    rvp.setY((rl.documentindex - m_firstline) * m_fontmetrics.height());
    rvp.setHeight(m_fontmetrics.height());

    painter->save();
        painter->translate(rvp.topLeft());
        textdocument.setTextWidth(rvp.width());
        textdocument.drawContents(painter);
    painter->restore();
}
