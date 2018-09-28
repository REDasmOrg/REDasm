#ifndef GRAPHTEXTITEM_H
#define GRAPHTEXTITEM_H

#include <QTextDocument>
#include "graphrectitem.h"

class GraphTextItem : public GraphRectItem
{
    Q_OBJECT

    public:
        explicit GraphTextItem(REDasm::Graphing::Vertex* v, QObject *parent = NULL);
        virtual QRect boundingRect() const;
        virtual void paint(QPainter* painter);

    protected:
        QTextDocument m_textdocument;
};

#endif // GRAPHTEXTITEM_H
