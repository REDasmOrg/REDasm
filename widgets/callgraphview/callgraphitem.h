#ifndef CALLGRAPHITEM_H
#define CALLGRAPHITEM_H

#include <QObject>
#include "../graphview/graphitems/graphitem.h"

class CallGraphItem : public GraphItem
{
    Q_OBJECT

    public:
        explicit CallGraphItem(REDasm::Graphing::Vertex* v, QObject *parent = nullptr);

    public:
        virtual QSize size() const;
        virtual void paint(QPainter* painter);

    private:
        QFont _font;
};

#endif // CALLGRAPHITEM_H
