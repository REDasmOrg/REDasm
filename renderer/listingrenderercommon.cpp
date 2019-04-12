#include "listingrenderercommon.h"
#include "../themeprovider.h"
#include <QApplication>
#include <QRegularExpression>
#include <QTextCharFormat>
#include <QTextDocument>
#include <QPalette>
#include <QPainter>

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

QString ListingRendererCommon::foregroundHtml(const std::string &s, const std::string& style, const REDasm::RendererLine& rl) const
{
    QColor c = THEME_VALUE(QString::fromStdString(style));
    return QString("<font data-line=\"%1\" style=\"color: %2\">%3</font>").arg(rl.documentindex).arg(c.name(), this->wordsToSpan(s, rl));
}

QString ListingRendererCommon::wordsToSpan(const std::string &s, const REDasm::RendererLine& rl) const
{
    QString spans = QString::fromStdString(s);
    spans.replace(QRegularExpression(REDASM_WORD_REGEX), QString("<span data-line=\"%1\">\\1</span>").arg(rl.documentindex));
    return spans;
}
