#include "listingtextrenderer.h"
#include "../../themeprovider.h"
#include <cmath>
#include <QPainter>
#include <QTextCharFormat>
#include <QTextDocument>
#include <QTextCursor>
#include <QAbstractTextDocumentLayout>

ListingTextRenderer::ListingTextRenderer(const QFont &font, REDasm::DisassemblerAPI *disassembler): REDasm::ListingRenderer(disassembler), m_fontmetrics(font), m_cursoractive(false) { }
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

    if(rl.highlighted)
    {
        QTextBlockFormat blockformat;
        blockformat.setBackground(THEME_VALUE("highlight"));
        textcursor.setBlockFormat(blockformat);

        if(m_cursoractive)
        {
            REDasm::ListingCursor* cur = m_document->cursor();
            textcursor.setPosition(cur->currentColumn());
            textcursor.movePosition(QTextCursor::Right, QTextCursor::KeepAnchor);

            QTextCharFormat charformat;
            charformat.setBackground(Qt::black);
            charformat.setForeground(Qt::white);
            textcursor.setCharFormat(charformat);
        }
    }

    painter->save();
        painter->translate(rvp.topLeft());
        textdocument.setTextWidth(rvp.width());
        textdocument.drawContents(painter);
    painter->restore();
}

void ListingTextRenderer::renderCursor(const REDasm::RendererLine& rl)
{
    QString s = QString::fromStdString(rl.text());
    REDasm::ListingCursor* cur = m_document->cursor();
    QRectF r;

    if(cur->currentColumn() < s.length())
        r.setX(m_fontmetrics.horizontalAdvance(s, cur->currentColumn()));
    else
        r.setX(cur->currentColumn() * m_fontmetrics.averageCharWidth());

    r.setY(rl.index * m_fontmetrics.height());
    r.setHeight(m_fontmetrics.height());
    r.setWidth(m_fontmetrics.averageCharWidth());

    QPainter* painter = reinterpret_cast<QPainter*>(rl.userdata);
    painter->fillRect(r, Qt::black);

    if(cur->currentColumn() < s.length())
    {
        painter->setPen(Qt::white);
        painter->drawText(r, Qt::AlignLeft | Qt::AlignTop, s.mid(cur->currentColumn(), 1));
    }
}
