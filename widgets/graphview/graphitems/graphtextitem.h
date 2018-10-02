#ifndef GRAPHTEXTITEM_H
#define GRAPHTEXTITEM_H

#include <QTextDocument>
#include "graphrectitem.h"

class GraphTextItem : public GraphRectItem
{
    Q_OBJECT

    public:
        explicit GraphTextItem(REDasm::Graphing::NodeData* data, QObject *parent = NULL);
        virtual void paint(QPainter* painter);

    protected:
        QTextDocument m_textdocument;
};

#endif // GRAPHTEXTITEM_H
