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
