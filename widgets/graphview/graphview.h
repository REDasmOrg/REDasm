#ifndef GRAPHVIEW_H
#define GRAPHVIEW_H

#include <QScrollArea>
#include "graphviewprivate.h"

class GraphView : public QScrollArea
{
    Q_OBJECT

    public:
        explicit GraphView(QWidget *parent = NULL);
        u64 itemPadding() const;
        u64 minimumSize() const;
        void addItem(GraphItem* item);
        void removeAll();

    public:
        bool overviewMode() const;
        void setOverviewMode(bool b);
        void setGraphSize(const QSize& size);

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
