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
        u64 itemPadding() const;
        bool overviewMode() const;
        void setOverviewMode(bool b);
        void setGraph(REDasm::Graphing::Graph* graph);
        void setGraphSize(const QSize& size);

    private:
        double getLayerHeight(GraphItem* item);
        void drawArrow(QPainter* painter, GraphItem* fromitem, GraphItem* toitem);
        void drawEdges(QPainter* painter, GraphItem* item);

    protected:
        virtual void paintEvent(QPaintEvent *event);
        virtual void wheelEvent(QWheelEvent *event);

    signals:
        void graphChanged();

    private:
        bool _overviewmode;
        double _zoomfactor;
        REDasm::Graphing::Graph* _graph;
        REDasm::Graphing::LayeredGraph _lgraph;
        QMap<REDasm::Graphing::vertex_id_t, GraphItem*> _itembyid;
        QHash<REDasm::Graphing::vertex_layer_t, double> _layerheight;
        QList<GraphItem*> _items;
        QSize _graphsize;
};

#endif // GRAPHVIEWPRIVATE_H
