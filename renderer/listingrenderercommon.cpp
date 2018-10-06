#include "listingrenderercommon.h"
#include "../themeprovider.h"
#include <QGuiApplication>
#include <QTextCharFormat>
#include <QPalette>

ListingRendererCommon::ListingRendererCommon(QTextDocument *textdocument, REDasm::ListingDocument *document): m_textdocument(textdocument), m_document(document)
{
    m_rgxwords.setPattern("([\\w\\.]+)");
    m_textcursor = QTextCursor(textdocument);
}

void ListingRendererCommon::insertLine(const REDasm::RendererLine &rl, bool showcursor)
{
    m_textcursor.movePosition(QTextCursor::End);
    m_textcursor.insertBlock(QTextBlockFormat());
    this->insertText(rl, showcursor);
}

void ListingRendererCommon::insertText(const REDasm::RendererLine &rl, bool showcursor)
{
    for(const REDasm::RendererFormat& rf : rl.formats)
    {
        QTextCharFormat charformat;

        if(!rf.style.empty())
            charformat.setForeground(THEME_VALUE(QString::fromStdString(rf.style)));

        m_textcursor.insertText(QString::fromStdString(rl.text.substr(rf.start, rf.length)), charformat);
    }

    REDasm::ListingCursor* cur = m_document->cursor();

    if(cur->isLineSelected(rl.line))
        this->highlightSelection(rl);
    else
        this->highlightWords(rl);

    if(rl.highlighted)
    {
        if(!cur->isLineSelected(rl.line))
            this->highlightLine();

        if(showcursor)
            this->showCursor();
    }
}

void ListingRendererCommon::insertHtmlLine(const REDasm::RendererLine &rl)
{
    m_textcursor.movePosition(QTextCursor::End);
    m_textcursor.insertText("<br>");
    this->insertHtmlText(rl);
}

void ListingRendererCommon::insertHtmlText(const REDasm::RendererLine &rl)
{
    QString content;

    for(const REDasm::RendererFormat& rf : rl.formats)
    {
       std::string s = rl.text.substr(rf.start, rf.length);

       if(!rf.style.empty())
           content += this->foregroundHtml(s, rf.style);
       else
           content += this->wordsToSpan(s);
    }

    m_textcursor.insertText(QString("<div style=\"display: inline-block\" id=\"%1\">%2</div>").arg(rl.line).arg(content));
}

QString ListingRendererCommon::foregroundHtml(const std::string &s, const std::string& style) const
{
    QColor c = THEME_VALUE(QString::fromStdString(style));
    return QString("<font style=\"color: %1\">%2</font>").arg(c.name(), this->wordsToSpan(s));
}

QString ListingRendererCommon::wordsToSpan(const std::string &s) const
{
    QString spans = QString::fromStdString(s);
    spans.replace(m_rgxwords, "<span>\\1</span>");
    return spans;
}

void ListingRendererCommon::showCursor()
{
    REDasm::ListingCursor* cur = m_document->cursor();
    m_textcursor.setPosition(cur->currentColumn());
    m_textcursor.movePosition(QTextCursor::Right, QTextCursor::KeepAnchor);

    QTextCharFormat charformat;
    charformat.setBackground(Qt::black);
    charformat.setForeground(Qt::white);
    m_textcursor.setCharFormat(charformat);
}

void ListingRendererCommon::highlightSelection(const REDasm::RendererLine &rl)
{
    QPalette palette = qApp->palette();
    REDasm::ListingCursor* cur = m_document->cursor();
    const REDasm::ListingCursor::Position& startsel = cur->startSelection();
    const REDasm::ListingCursor::Position& endsel = cur->endSelection();

    if(startsel.first == endsel.first)
    {
        m_textcursor.setPosition(startsel.second);
        m_textcursor.movePosition(QTextCursor::Right, QTextCursor::KeepAnchor, endsel.second - startsel.second + 1);
    }
    else
    {
        if(rl.line == startsel.first)
            m_textcursor.setPosition(startsel.second);
        else
            m_textcursor.setPosition(0);

        if(rl.line == endsel.first)
            m_textcursor.movePosition(QTextCursor::Right, QTextCursor::KeepAnchor, endsel.second + 1);
        else
            m_textcursor.movePosition(QTextCursor::EndOfLine, QTextCursor::KeepAnchor);
    }

    QTextCharFormat charformat;
    charformat.setBackground(palette.color(QPalette::Highlight));
    charformat.setForeground(palette.color(QPalette::HighlightedText));
    m_textcursor.setCharFormat(charformat);
}

void ListingRendererCommon::highlightWords(const REDasm::RendererLine &rl)
{
    if(m_document->cursor()->wordUnderCursor().empty())
        return;

    QTextCharFormat charformat;
    charformat.setBackground(THEME_VALUE("highlight"));

    QRegularExpression rgx(QString::fromStdString(m_document->cursor()->wordUnderCursor()));
    QRegularExpressionMatchIterator it = rgx.globalMatch(QString::fromStdString(rl.text));

    while(it.hasNext())
    {
        QRegularExpressionMatch match = it.next();

        m_textcursor.setPosition(match.capturedStart());
        m_textcursor.movePosition(QTextCursor::Right, QTextCursor::KeepAnchor, match.capturedLength());
        m_textcursor.setCharFormat(charformat);
    }
}

void ListingRendererCommon::highlightLine()
{
    QTextBlockFormat blockformat;
    blockformat.setBackground(THEME_VALUE("seek"));
    m_textcursor.setBlockFormat(blockformat);
}
