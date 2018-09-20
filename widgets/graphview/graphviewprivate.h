#ifndef GRAPHVIEWPRIVATE_H
#define GRAPHVIEWPRIVATE_H

#include <QWidget>
#include <QList>
#include <QMap>
#include "../../redasm/graph/graph.h"
#include "graphitems/graphitem.h"

class GraphViewPrivate : public QWidget
{
    Q_OBJECT

    public:
        explicit GraphViewPrivate(QWidget *parent = NULL);
        const QSize& graphSize() const;
        void addItem(GraphItem* item);
        void removeAll();

    public:
        bool overviewMode() const;
        void setOverviewMode(bool b);
        void setGraph(REDasm::Graphing::Graph* graph);
        void setGraphSize(const QSize& size);

    private:
        double getLayerHeight(GraphItem* item);
        double getEdgeOffset(GraphItem* fromitem, GraphItem* toitem) const;
        void drawEdge(QPainter* painter, GraphItem* fromitem, GraphItem* toitem, double offset);
        void drawEdges(QPainter* painter, GraphItem* item);

    protected:
        virtual void paintEvent(QPaintEvent *event);
        virtual void wheelEvent(QWheelEvent *event);

    signals:
        void graphChanged();

    private:
        bool m_overviewmode;
        double m_zoomfactor;
        REDasm::Graphing::Graph* m_graph;
        REDasm::Graphing::LayeredGraph m_lgraph;
        QMap<REDasm::Graphing::vertex_id_t, GraphItem*> m_itembyid;
        QHash<REDasm::Graphing::vertex_layer_t, double> m_layerheight;
        QList<GraphItem*> m_items;
        QSize m_graphsize;
};

#endif // GRAPHVIEWPRIVATE_H
