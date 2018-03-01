#ifndef GRAPHITEM_H
#define GRAPHITEM_H

#include <QObject>
#include <QPainter>
#include <QPoint>
#include "../../redasm/graph/vertex.h"

class GraphItem : public QObject
{
    Q_OBJECT

    public:
        explicit GraphItem(REDasm::Graphing::Vertex* v, QObject *parent = nullptr);
        const REDasm::Graphing::Vertex *vertex() const;
        QColor borderColor() const;
        QRect rect() const;
        const QPoint& position() const;
        void move(int x, int y);

    public:
        virtual QSize size() const = 0;
        virtual void paint(QPainter* painter) = 0;

    private:
        QPoint _pos;
        REDasm::Graphing::Vertex* _vertex;

};

#endif // GRAPHITEM_H
