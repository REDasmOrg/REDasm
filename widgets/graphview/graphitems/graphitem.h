#ifndef GRAPHITEM_H
#define GRAPHITEM_H

#include <QObject>
#include <QPainter>
#include <QPoint>
#include <QSize>
#include "../../redasm/graph/nodedata.h"

class GraphItem : public QObject
{
    Q_OBJECT

    public:
        explicit GraphItem(REDasm::Graphing::NodeData* data, QObject *parent = NULL);
        virtual QRectF boundingRect() const;
        virtual void paint(QPainter* painter);

    private:
        REDasm::Graphing::NodeData* m_data;

};

#endif // GRAPHITEM_H
