#ifndef GRAPHVIEW_H
#define GRAPHVIEW_H

#include <QScrollArea>
#include "graphviewprivate.h"

class GraphView : public QScrollArea
{
    Q_OBJECT

    public:
        explicit GraphView(QWidget *parent = NULL);
        GraphItem *addRoot(GraphItem* item);
        void addEdge(GraphItem* fromitem, GraphItem* toitem);
        void removeAll();
        void beginInsertion();
        void endInsertion();

    public:
        bool overviewMode() const;
        void setOverviewMode(bool b);

    private slots:
        void resizeGraphView();

    private:
        GraphViewPrivate* _graphview_p;
};

#endif // GRAPHVIEW_H
