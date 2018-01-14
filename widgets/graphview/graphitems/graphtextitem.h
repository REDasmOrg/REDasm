#ifndef GRAPHTEXTITEM_H
#define GRAPHTEXTITEM_H

#include <QTextDocument>
#include <QTextCursor>
#include "graphitem.h"

class GraphTextItem : public GraphItem
{
    Q_OBJECT

    public:
        explicit GraphTextItem(QObject *parent = NULL);
        GraphTextItem(const QString& text, QObject *parent = NULL);
        QTextDocument* document();
        QTextCursor textCursor();
        QFont font();
        void setText(const QString& s);
        void setFont(const QFont& font);

    public:
        virtual QSize size() const;
        virtual void paint(QPainter *painter);

    private:
        QTextDocument _document;
        QTextCursor _textcursor;
};

#endif // GRAPHTEXTITEM_H
