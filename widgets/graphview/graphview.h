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
        virtual GraphItem* createItem(REDasm::Graphing::NodeData* data);
        virtual void scrollContentsBy(int dx, int dy);
        virtual void paintEvent(QPaintEvent*e);
        virtual void wheelEvent(QWheelEvent* e);
        virtual void resizeEvent(QResizeEvent* e);
        virtual void mousePressEvent(QMouseEvent* e);
        virtual void mouseReleaseEvent(QMouseEvent* e);
        virtual void mouseMoveEvent(QMouseEvent* e);

    private:
        void updateScrollBars();
        void drawBlocks(QPainter* painter);
        void drawEdges(QPainter* painter);
        void drawEdge(QPainter *painter, ogdf::EdgeElement *edge);

    private:
        QPoint m_lastpos;
        std::unique_ptr<REDasm::Graphing::Graph> m_graph;
        QList<GraphItem*> m_items;
};

#endif // GRAPHVIEW_H
