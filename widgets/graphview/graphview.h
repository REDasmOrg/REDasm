#ifndef GRAPHVIEW_H
#define GRAPHVIEW_H

#include <QWebEngineView>
#include <redasm/graph/graph.h>
#include <QMenu>

class GraphView : public QWebEngineView
{
    Q_OBJECT

    public:
        explicit GraphView(QWidget *parent = NULL);
        void setGraph(const REDasm::Graphing::Graph &graph);

    protected:
        virtual void configureActions();
        virtual void dragEnterEvent(QDragEnterEvent* e);
        virtual QString getNodeTitle(const REDasm::Graphing::Node* n) const;
        virtual QString getNodeContent(const REDasm::Graphing::Node* n) const = 0;
        virtual QColor getEdgeColor(const REDasm::Graphing::Node* from, const REDasm::Graphing::Node* to) const;
        void appendCSS(const QString& css);
        void focusOnLine(int line);
        void zoomOn(int line);

    protected slots:
        virtual void initializePage();

    protected:
        QMenu* m_contextmenu;

    private:
        QString nodeTitle(const REDasm::Graphing::Node *n) const;
        void generateNodes(const REDasm::Graphing::Graph& graph);
        void generateEdges(const REDasm::Graphing::Graph& graph);
};

#endif // GRAPHVIEW_H
