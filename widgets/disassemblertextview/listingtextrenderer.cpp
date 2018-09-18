#include "listingtextrenderer.h"
#include "../../themeprovider.h"
#include <cmath>
#include <QApplication>
#include <QTextCharFormat>
#include <QTextDocument>
#include <QPalette>
#include <QPainter>

ListingTextRenderer::ListingTextRenderer(const QFont &font, REDasm::DisassemblerAPI *disassembler): REDasm::ListingRenderer(disassembler), m_fontmetrics(font), m_cursoractive(false)
{
    m_rgxwords.setPattern("[\\w\\.]+");
}

ListingTextRenderer::~ListingTextRenderer() { }

REDasm::ListingCursor::Position ListingTextRenderer::hitTest(const QPointF &pos, int firstline)
{
    REDasm::ListingCursor::Position cp;
    cp.first = firstline + std::floor(pos.y() / m_fontmetrics.height());
    cp.second = -1;

    REDasm::RendererLine rl;
    this->getRendererLine(cp.first, rl);
    std::string s = rl.text();

    for(size_t i = 0; i < s.length(); i++)
    {
        QRect r = m_fontmetrics.boundingRect(QString::fromStdString(s.substr(0, i + 1)));

        if(!r.contains(QPoint(pos.x(), r.y())))
            continue;

        cp.second = i;
        break;
    }

    if(cp.second == -1)
        cp.second = s.length() - 1;

    this->updateWordUnderCursor(s, cp);
    return cp;
}

ListingTextRenderer::Range ListingTextRenderer::wordHitTest(const QPointF &pos, int firstline)
{
    REDasm::ListingCursor::Position cp = this->hitTest(pos, firstline);

    REDasm::RendererLine rl;
    this->getRendererLine(cp.first, rl);

    int p = -1;
    std::string s = rl.text(), res = this->findWordUnderCursor(s, cp, &p);
    return std::make_pair(p, p + res.length() - 1);
}

void ListingTextRenderer::updateWordUnderCursor()
{
    REDasm::ListingCursor* cur = m_document->cursor();
    REDasm::RendererLine rl;

    this->getRendererLine(cur->currentLine(), rl);
    this->updateWordUnderCursor(rl.text(), cur->currentPosition());
}

void ListingTextRenderer::toggleCursor() { m_cursoractive = !m_cursoractive; }
void ListingTextRenderer::enableCursor() { m_cursoractive = true; }
void ListingTextRenderer::disableCursor() { m_cursoractive = false; }

void ListingTextRenderer::renderLine(const REDasm::RendererLine &rl)
{
    REDasm::ListingCursor* cur = m_document->cursor();
    QPainter* painter = reinterpret_cast<QPainter*>(rl.userdata);
    QRect rvp = painter->viewport();
    rvp.setY(rl.index * m_fontmetrics.height());
    rvp.setHeight(m_fontmetrics.height());

    QTextDocument textdocument;
    textdocument.setDocumentMargin(0);
    textdocument.setUndoRedoEnabled(false);
    textdocument.setDefaultFont(painter->font());

    QTextCursor textcursor(&textdocument);

    for(const REDasm::RendererFormat& rf : rl.formats)
    {
        QTextCharFormat charformat;

        if(!rf.style.empty())
            charformat.setForeground(THEME_VALUE(QString::fromStdString(rf.style)));

        textcursor.insertText(QString::fromStdString(rf.text), charformat);
    }

    if(cur->isLineSelected(rl.line))
        this->renderSelection(textcursor, rl);
    else
        this->highlightWords(textcursor, rl);

    if(rl.highlighted)
    {
        if(!cur->isLineSelected(rl.line))
            this->highlightLine(textcursor);

        if(m_cursoractive)
            this->renderCursor(textcursor);
    }

    painter->save();
        painter->translate(rvp.topLeft());
        textdocument.drawContents(painter);
    painter->restore();
}

std::string ListingTextRenderer::findWordUnderCursor(const std::string &s, const REDasm::ListingCursor::Position &cp, int* pos)
{
    QRegularExpressionMatchIterator it = m_rgxwords.globalMatch(QString::fromStdString(s));

    while(it.hasNext())
    {
        QRegularExpressionMatch match = it.next();

        if((cp.second < match.capturedStart()) || (cp.second > match.capturedEnd()))
            continue;

        if(pos)
            *pos = match.capturedStart();

        return match.captured().toStdString();
    }

    return std::string();
}

void ListingTextRenderer::updateWordUnderCursor(const std::string &s, const REDasm::ListingCursor::Position &cp)
{
    m_document->cursor()->setWordUnderCursor(this->findWordUnderCursor(s, cp));
}

void ListingTextRenderer::highlightWords(QTextCursor& textcursor, const REDasm::RendererLine &rl) const
{
    if(m_document->cursor()->wordUnderCursor().empty())
        return;

    QTextCharFormat charformat;
    charformat.setBackground(THEME_VALUE("highlight"));

    QRegularExpression rgx(QString::fromStdString(m_document->cursor()->wordUnderCursor()));
    QRegularExpressionMatchIterator it = rgx.globalMatch(QString::fromStdString(rl.text()));

    while(it.hasNext())
    {
        QRegularExpressionMatch match = it.next();

        textcursor.setPosition(match.capturedStart());
        textcursor.movePosition(QTextCursor::Right, QTextCursor::KeepAnchor, match.capturedLength());
        textcursor.setCharFormat(charformat);
    }
}

void ListingTextRenderer::highlightLine(QTextCursor &textcursor) const
{
    QTextBlockFormat blockformat;
    blockformat.setBackground(THEME_VALUE("seek"));
    textcursor.setBlockFormat(blockformat);
}

void ListingTextRenderer::renderCursor(QTextCursor &textcursor) const
{
    REDasm::ListingCursor* cur = m_document->cursor();
    textcursor.setPosition(cur->currentColumn());
    textcursor.movePosition(QTextCursor::Right, QTextCursor::KeepAnchor);

    QTextCharFormat charformat;
    charformat.setBackground(Qt::black);
    charformat.setForeground(Qt::white);
    textcursor.setCharFormat(charformat);
}

void ListingTextRenderer::renderSelection(QTextCursor &textcursor, const REDasm::RendererLine& rl) const
{
    QPalette palette = qApp->palette();
    REDasm::ListingCursor* cur = m_document->cursor();
    const REDasm::ListingCursor::Position& startsel = cur->startSelection();
    const REDasm::ListingCursor::Position& endsel = cur->endSelection();

    if(startsel.first == endsel.first)
    {
        textcursor.setPosition(startsel.second);
        textcursor.movePosition(QTextCursor::Right, QTextCursor::KeepAnchor, endsel.second - startsel.second + 1);
    }
    else
    {
        if(rl.line == startsel.first)
            textcursor.setPosition(startsel.second);
        else
            textcursor.setPosition(0);

        if(rl.line == endsel.first)
            textcursor.movePosition(QTextCursor::Right, QTextCursor::KeepAnchor, endsel.second + 1);
        else
            textcursor.movePosition(QTextCursor::EndOfLine, QTextCursor::KeepAnchor);
    }

    QTextCharFormat charformat;
    charformat.setBackground(palette.color(QPalette::Highlight));
    charformat.setForeground(palette.color(QPalette::HighlightedText));
    textcursor.setCharFormat(charformat);
}
