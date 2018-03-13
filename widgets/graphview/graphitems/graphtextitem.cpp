#include "graphtextitem.h"

GraphTextItem::GraphTextItem(REDasm::Graphing::Vertex *v, QObject *parent) : GraphItem(v, parent)
{
    this->_textcursor = QTextCursor(&this->_document);
}

GraphTextItem::GraphTextItem(REDasm::Graphing::Vertex *v, const QString &text, QObject *parent) : GraphItem(v, parent)
{
    this->_textcursor = QTextCursor(&this->_document);
    this->setText(text);
}

QTextDocument *GraphTextItem::document()
{
    return &this->_document;
}

QTextCursor GraphTextItem::textCursor()
{
    return this->_textcursor;
}

QFont GraphTextItem::font() const
{
    return this->_document.defaultFont();
}

void GraphTextItem::setText(const QString &s)
{
    this->_document.clear();
    this->_textcursor.insertText(s);
}

void GraphTextItem::setFont(const QFont &font)
{
    this->_document.setDefaultFont(font);
}

QSize GraphTextItem::size() const
{
    return this->_document.size().toSize();
}

void GraphTextItem::paint(QPainter *painter)
{
    painter->save();
        painter->translate(this->origin());
        this->_document.drawContents(painter);
    painter->restore();
}

QPoint GraphTextItem::origin() const { return this->position(); }
