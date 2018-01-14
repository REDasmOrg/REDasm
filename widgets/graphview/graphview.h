#ifndef GRAPHVIEW_H
#define GRAPHVIEW_H

#include <QScrollArea>
#include "graphviewprivate.h"

class GraphView : public QScrollArea
{
    Q_OBJECT

    public:
        explicit GraphView(QWidget *parent = NULL);
        GraphItem *addItem(GraphItem* item);
        void addEdge(GraphItem* fromitem, GraphItem* toitem);

    public:
        bool overviewMode() const;
        void setOverviewMode(bool b);

    private slots:
        void resizeGraphView();

    private:
        GraphViewPrivate* _graphview_p;
};

#endif // GRAPHVIEW_H
