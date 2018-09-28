#ifndef GRAPHVIEW_H
#define GRAPHVIEW_H

#include <QAbstractScrollArea>
#include "../../redasm/graph/graph.h"
#include "graphitems/graphitem.h"

class GraphView : public QAbstractScrollArea
{
    Q_OBJECT

    public:
        explicit GraphView(QWidget *parent = NULL);
        void setGraph(REDasm::Graphing::Graph *graph);

    protected:
        virtual GraphItem* createItem(REDasm::Graphing::Vertex* v);
        virtual void paintEvent(QPaintEvent*e);
        virtual void wheelEvent(QWheelEvent* e);
        virtual void resizeEvent(QResizeEvent* e);
        virtual void mousePressEvent(QMouseEvent* e);
        virtual void mouseReleaseEvent(QMouseEvent* e);
        virtual void mouseMoveEvent(QMouseEvent* e);

    private:
        int getEdgesHeight(const REDasm::Graphing::VertexList& vl) const;
        int getEdgeIndex(GraphItem* from, GraphItem* to) const;
        int getLayerHeight(GraphItem* item) const;
        void drawBlocks(QPainter* painter);
        void drawEdges(QPainter* painter);
        void drawEdge(QPainter *painter, GraphItem* from, GraphItem* to);

    private:
        QPoint m_lastpos;
        std::unique_ptr<REDasm::Graphing::Graph> m_graph;
        REDasm::Graphing::LayeredGraph m_lgraph;
        QHash<REDasm::Graphing::vertex_id_t, GraphItem*> m_items;
};

#endif // GRAPHVIEW_H
