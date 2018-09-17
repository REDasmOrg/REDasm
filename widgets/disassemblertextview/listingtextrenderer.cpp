#include "listingtextrenderer.h"
#include "../../themeprovider.h"
#include <cmath>
#include <QTextCharFormat>
#include <QTextDocument>
#include <QPainter>

ListingTextRenderer::ListingTextRenderer(const QFont &font, REDasm::DisassemblerAPI *disassembler): REDasm::ListingRenderer(disassembler), m_fontmetrics(font), m_cursoractive(false)
{
    m_rgxwords.setPattern("[\\w\\.]+");
}

ListingTextRenderer::~ListingTextRenderer() { }

REDasm::ListingCursor::Position ListingTextRenderer::hitTest(const QPointF &pos, QScrollBar *vscrollbar)
{
    REDasm::ListingCursor::Position cp;
    cp.first = vscrollbar->value() + std::floor(pos.y() / m_fontmetrics.height());
    cp.second = -1;

    REDasm::RendererLine rl;
    this->getRendererLine(cp.first, rl);
    QString s = QString::fromStdString(rl.text());

    for(int i = 0; i < s.length(); i++)
    {
        QRect r = m_fontmetrics.boundingRect(s.left(i + 1));

        if(!r.contains(QPoint(pos.x(), r.y())))
            continue;

        cp.second = i;
        break;
    }

    if(cp.second == -1)
        cp.second = s.length() - 1;

    this->findWordUnderCursor(s, cp);
    return cp;
}

void ListingTextRenderer::toggleCursor() { m_cursoractive = !m_cursoractive; }

void ListingTextRenderer::renderLine(const REDasm::RendererLine &rl)
{
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

    this->highlightWords(textcursor, rl);

    if(rl.highlighted)
    {
        this->highlightLine(textcursor);

        if(m_cursoractive)
            this->renderCursor(textcursor);
    }

    painter->save();
        painter->translate(rvp.topLeft());
        textdocument.setTextWidth(rvp.width());
        textdocument.drawContents(painter);
    painter->restore();
}

void ListingTextRenderer::findWordUnderCursor(const QString &s, const REDasm::ListingCursor::Position &cp)
{
    QRegularExpressionMatchIterator it = m_rgxwords.globalMatch(s);

    while(it.hasNext())
    {
        QRegularExpressionMatch match = it.next();

        if((cp.second < match.capturedStart()) || (cp.second > match.capturedEnd()))
            continue;

        m_document->cursor()->setWordUnderCursor(match.captured().toStdString());
        return;
    }

    m_document->cursor()->clearWordUnderCursor();
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
