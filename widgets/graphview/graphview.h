#ifndef GRAPHVIEW_H
#define GRAPHVIEW_H

#include <QScrollArea>
#include "../../redasm/graph/graph.h"
#include "graphviewprivate.h"

class GraphView : public QScrollArea
{
    Q_OBJECT

    public:
        explicit GraphView(QWidget *parent = NULL);
        void render(const REDasm::Graphing::Graph *graph);
        u64 itemPadding() const;
        u64 minimumSize() const;

    public:
        bool overviewMode() const;
        void setOverviewMode(bool b);
        void setGraphSize(const QSize& size);

    protected:
        virtual GraphItem* createItem(REDasm::Graphing::Vertex* v) = 0;
        virtual void resizeEvent(QResizeEvent* e);
        virtual void mousePressEvent(QMouseEvent* e);
        virtual void mouseReleaseEvent(QMouseEvent* e);
        virtual void mouseMoveEvent(QMouseEvent* e);

    private:
        void addItem(GraphItem* item);
        void removeAll();

    private slots:
        void resizeGraphView();

    private:
        GraphViewPrivate* _graphview_p;
        QPoint _lastpos;
};

#endif // GRAPHVIEW_H
