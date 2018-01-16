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

    protected:
        virtual void mousePressEvent(QMouseEvent* e);
        virtual void mouseReleaseEvent(QMouseEvent* e);
        virtual void mouseMoveEvent(QMouseEvent* e);

    private slots:
        void resizeGraphView();

    private:
        GraphViewPrivate* _graphview_p;
        QPoint _lastpos;
};

#endif // GRAPHVIEW_H
