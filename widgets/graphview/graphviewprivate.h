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

    public:
        explicit GraphViewPrivate(QWidget *parent = NULL);
        u64 itemPadding() const;
        const QSize& graphSize() const;
        void addItem(GraphItem* item);
        void removeAll();

    public:
        bool overviewMode() const;
        void setOverviewMode(bool b);

    private:
        void drawArrow(QPainter* painter, GraphItem* fromitem, GraphItem* toitem);
        void drawEdges(QPainter* painter, GraphItem* item);

    protected:
        virtual void paintEvent(QPaintEvent *event);

    signals:
        void graphChanged();

    private:
        bool _overviewmode;
        GraphItem* _rootitem;
        QList<GraphItem*> _items;
        QSize _graphsize;
};

#endif // GRAPHVIEWPRIVATE_H
