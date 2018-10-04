#include "graphview.h"
#include <QWebEngineSettings>
#include <QFontDatabase>
#include "../../themeprovider.h"

#define GRAPH_MARGINS 20

GraphView::GraphView(QWidget *parent): QWebEngineView(parent), m_graphready(false)
{
    connect(this, &GraphView::loadFinished, this, &GraphView::loadTheme);

    this->page()->setBackgroundColor("azure");
    this->load(QUrl("qrc:/web/graph.html"));
}

void GraphView::setGraph(const REDasm::Graphing::Graph &graph)
{
    m_graphready = false;

    this->page()->runJavaScript("var g = new dagre.graphlib.Graph();"
                                "g.setDefaultEdgeLabel(function() { return { }; });"
                                "g.setGraph({ });");

    this->generateNodes(graph);
    this->generateEdges(graph);

    this->page()->runJavaScript("d3.selectAll('svg > *').remove();"
                                "var svg = d3.select('svg');"
                                "svg.append('g').call(new dagreD3.render(), g);" +
                                QString("svg.attr('width', g.graph().width + %1);").arg(GRAPH_MARGINS) +
                                QString("svg.attr('height', g.graph().height + %1);").arg(GRAPH_MARGINS));
    m_graphready = true;
    this->redraw();
}

void GraphView::resizeEvent(QResizeEvent *e)
{
    QWebEngineView::resizeEvent(e);
    this->redraw();
}

void GraphView::loadTheme()
{
    QFont font = QFontDatabase::systemFont(QFontDatabase::FixedFont);

    QString generalcss = "html {"
                             "font-family:" + font.family() + ";" +
                             "font-size" + QString::number(font.pointSize()) + "pt;" +
                         "}";

    QString blockcss = ".node rect {"
                           "fill: white;"
                           "stroke: black;"
                       "}"
                       ".edgePath path {"
                           "stroke: black;"
                       "}";

    this->appendCSS(generalcss);
    this->appendCSS(blockcss);
}

void GraphView::generateNodes(const REDasm::Graphing::Graph &graph)
{
    for(auto& n : graph)
    {
        QString content = this->getNodeContent(n.get());

        this->page()->runJavaScript(QString("g.setNode(%1, { labelType: 'html', "
                                            "                label: '%2' });").arg(n->id).arg(content));
    }
}

void GraphView::generateEdges(const REDasm::Graphing::Graph &graph)
{
    for(auto& n : graph)
    {
        const REDasm::Graphing::AdjacencyList& edges = graph.edges(n);

        for(auto& e : edges)
            this->page()->runJavaScript(QString("g.setEdge(%1, %2);").arg(n->id).arg(e->id));
    }
}

void GraphView::appendCSS(const QString &css)
{
    this->page()->runJavaScript("var css = document.createElement('style');"
                                "css.type = 'text/css';"
                                "document.head.appendChild(css);"
                                "css.innerText = '" + css + "';");
}

void GraphView::redraw()
{
    if(!m_graphready)
        return;

    this->page()->runJavaScript("var width = " + QString::number(this->width()) + ";" +
                                "var height = " + QString::number(this->height()) + ";" +
                                "var mid = (width - g.graph().width) / 2;" +
                                QString("svg.attr('transform', 'translate(' + mid  + ', %1)');").arg(GRAPH_MARGINS));
}
