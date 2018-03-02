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
        void drawArrow(QPainter* painter, GraphItem* fromitem, GraphItem* toitem);
        void drawEdges(QPainter* painter, GraphItem* item);

    protected:
        virtual void paintEvent(QPaintEvent *event);

    signals:
        void graphChanged();

    private:
        bool _overviewmode;
        REDasm::Graphing::Graph* _graph;
        QMap<REDasm::Graphing::vertex_id_t, GraphItem*> _itembyid;
        QList<GraphItem*> _items;
        QSize _graphsize;
};

#endif // GRAPHVIEWPRIVATE_H
