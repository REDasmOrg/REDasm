#ifndef GRAPHITEM_H
#define GRAPHITEM_H

#include <QObject>
#include <QPainter>
#include <QPoint>
#include <QSize>
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
        void resize(int width, int height);

    public:
        virtual QSize size() const;
        virtual void paint(QPainter* painter);

    private:
        QPoint _pos;
        QSize _defaultsize;
        REDasm::Graphing::Vertex* _vertex;

};

#endif // GRAPHITEM_H
