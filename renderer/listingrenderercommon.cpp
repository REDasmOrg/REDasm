#include "listingrenderercommon.h"
#include "../redasmsettings.h"
#include "../themeprovider.h"
#include <QApplication>
#include <QRegularExpression>
#include <QTextCharFormat>
#include <QTextDocument>
#include <QPalette>
#include <QPainter>

ListingRendererCommon::ListingRendererCommon(REDasm::DisassemblerAPI *disassembler): REDasm::ListingRenderer(disassembler), m_fontmetrics(REDasmSettings::font()), m_maxwidth(0), m_firstline(0) { }

void ListingRendererCommon::moveTo(const QPointF &pos)
{
    REDasm::ListingCursor::Position cp = this->hitTest(pos);
    m_cursor->moveTo(cp.first, cp.second);
}

void ListingRendererCommon::select(const QPointF &pos)
{
    REDasm::ListingCursor::Position cp = this->hitTest(pos);
    m_cursor->select(cp.first, cp.second);
}

REDasm::ListingCursor::Position ListingRendererCommon::hitTest(const QPointF &pos)
{
    REDasm::ListingCursor::Position cp;
    cp.first = std::min(static_cast<u64>(m_firstline + std::floor(pos.y() / m_fontmetrics.height())), m_document->lastLine());
    cp.second = std::numeric_limits<u64>::max();

    REDasm::RendererLine rl(true);

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

std::string ListingRendererCommon::getWordFromPos(const QPointF &pos, REDasm::ListingRenderer::Range* wordpos)
{
    REDasm::ListingCursor::Position cp = this->hitTest(pos);
    return this->wordFromPosition(cp, wordpos);
}

REDasm::ListingRenderer::Range ListingRendererCommon::wordHitTest(const QPointF &pos)
{
    REDasm::ListingRenderer::Range wordpos;
    this->getWordFromPos(pos, &wordpos);
    return wordpos;
}

void ListingRendererCommon::setFirstVisibleLine(u64 line) { m_firstline = line; }
const QFontMetricsF ListingRendererCommon::fontMetrics() const { return m_fontmetrics; }
qreal ListingRendererCommon::maxWidth() const { return m_maxwidth; }

void ListingRendererCommon::insertText(const REDasm::RendererLine &rl, QTextCursor *textcursor)
{
    if(rl.index > 0)
    {
        textcursor->movePosition(QTextCursor::End);
        textcursor->insertBlock(QTextBlockFormat());
    }

    for(const REDasm::RendererFormat& rf : rl.formats)
    {
        QTextCharFormat charformat;

        if(!rf.fgstyle.empty())
        {
            if((rf.fgstyle == "cursor_fg") || (rf.fgstyle == "selection_fg"))
                charformat.setForeground(qApp->palette().color(QPalette::HighlightedText));
            else
                charformat.setForeground(THEME_VALUE(QString::fromStdString(rf.fgstyle)));
        }

        if(!rf.bgstyle.empty())
        {
            if(rf.bgstyle == "cursor_bg")
                charformat.setBackground(qApp->palette().color(QPalette::WindowText));
            else if(rf.bgstyle == "selection_bg")
                charformat.setBackground(qApp->palette().color(QPalette::Highlight));
            else
                charformat.setBackground(THEME_VALUE(QString::fromStdString(rf.bgstyle)));
        }

        textcursor->insertText(QString::fromStdString(rl.formatText(rf)), charformat);
    }

    if(!rl.highlighted)
        return;

    QTextBlockFormat blockformat;
    blockformat.setBackground(THEME_VALUE("seek"));
    textcursor->setBlockFormat(blockformat);
}

void ListingRendererCommon::renderText(const REDasm::RendererLine &rl, float x, float y, const QFontMetricsF& fm)
{
    QPainter* painter = reinterpret_cast<QPainter*>(rl.userdata);

    if(rl.highlighted)
    {
        QRect vpr = painter->viewport();
        painter->fillRect(0, y, vpr.width(), fm.height(), THEME_VALUE("seek"));
    }

    for(const REDasm::RendererFormat& rf : rl.formats)
    {
        if(!rf.fgstyle.empty())
        {
            if((rf.fgstyle == "cursor_fg") || (rf.fgstyle == "selection_fg"))
                painter->setPen(qApp->palette().color(QPalette::HighlightedText));
            else
                painter->setPen(THEME_VALUE(QString::fromStdString(rf.fgstyle)));
        }
        else
            painter->setPen(qApp->palette().color(QPalette::WindowText));

        QString chunk = QString::fromStdString(rl.formatText(rf));
        QRectF chunkrect = painter->boundingRect(QRectF(x, y, fm.width(chunk), fm.height()), Qt::TextIncludeTrailingSpaces, chunk);

        if(!rf.bgstyle.empty())
        {
            if(rf.bgstyle == "cursor_bg")
                painter->fillRect(chunkrect, qApp->palette().color(QPalette::WindowText));
            else if(rf.bgstyle == "selection_bg")
                painter->fillRect(chunkrect, qApp->palette().color(QPalette::Highlight));
            else
                painter->fillRect(chunkrect, THEME_VALUE(QString::fromStdString(rf.bgstyle)));
        }

        painter->drawText(chunkrect, Qt::TextSingleLine, chunk);
        x += chunkrect.width();
    }
}
