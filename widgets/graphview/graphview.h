#ifndef GRAPHVIEW_H
#define GRAPHVIEW_H

#include <QAbstractScrollArea>
#include <QWebEngineView>
#include "../../redasm/graph/graph.h"

class GraphView : public QWebEngineView
{
    Q_OBJECT

    public:
        explicit GraphView(QWidget *parent = NULL);
        void setGraph(const REDasm::Graphing::Graph &graph);

    protected:
        virtual QString getNodeContent(const REDasm::Graphing::Node* n) = 0;
        virtual void resizeEvent(QResizeEvent* e);

    private slots:
        void loadTheme();

    private:
        void generateNodes(const REDasm::Graphing::Graph& graph);
        void generateEdges(const REDasm::Graphing::Graph& graph);
        void appendCSS(const QString& css);
        void redraw();

    private:
        bool m_graphready;
};

#endif // GRAPHVIEW_H
