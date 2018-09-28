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
        explicit GraphItem(REDasm::Graphing::Vertex* v, QObject *parent = NULL);
        REDasm::Graphing::Vertex *vertex();
        REDasm::Graphing::vertex_index_t index() const;
        REDasm::Graphing::vertex_layer_t layer() const;
        REDasm::Graphing::vertex_id_t id() const;
        bool isFake() const;
        void setPosition(int x, int y);

    public:
        virtual QRect boundingRect() const;
        virtual void paint(QPainter* painter);

    private:
        QPoint m_pos;
        REDasm::Graphing::Vertex* m_vertex;

};

#endif // GRAPHITEM_H
