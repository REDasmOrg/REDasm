#ifndef GRAPHVIEWPRIVATE_H
#define GRAPHVIEWPRIVATE_H

#include <QWidget>
#include <QList>
#include <QMap>
#include <QSet>
#include "graphitems/graphitem.h"

class GraphViewPrivate : public QWidget
{
    Q_OBJECT

    private:
        typedef QList<GraphItem*> GraphItemList;
        typedef QMap<GraphItem*, GraphItemList> GraphItemMap;
        typedef QMapIterator<GraphItem*, GraphItemList> GraphItemMapIterator;

    public:
        explicit GraphViewPrivate(QWidget *parent = NULL);
        const QSize& graphSize() const;
        GraphItem *addRoot(GraphItem* item);
        void addEdge(GraphItem* fromitem, GraphItem* toitem);
        void removeAll();
        void beginInsertion();
        void endInsertion();

    public:
        bool overviewMode() const;
        void setOverviewMode(bool b);

    private:
        void drawArrow(QPainter* painter, GraphItem* fromitem, GraphItem* toitem);
        void drawEdges(QPainter* painter, GraphItem* item);
        void addItem(GraphItem* item, bool dolayout);
        QSize edgesSize(GraphItem* item) const;
        QSize layoutEdges(GraphItem* item);
        void layoutRoot();

    protected:
        virtual void paintEvent(QPaintEvent*);

    signals:
        void graphDrawed();

    private:
        bool _overviewmode, _locklayout;
        GraphItem* _rootitem;
        GraphItemMap _graph;
        QList<GraphItem*> _items;
        QSet<GraphItem*> _processed;
        QSize _graphsize;
};

#endif // GRAPHVIEWPRIVATE_H
