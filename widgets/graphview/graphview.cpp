#include "graphview.h"
#include <QWebEngineSettings>
#include <QFontDatabase>
#include "../../themeprovider.h"

#define GRAPH_MARGINS 20

GraphView::GraphView(QWidget *parent): QWebEngineView(parent)
{
    connect(this, &GraphView::loadFinished, this, &GraphView::initializePage);

    this->settings()->setAttribute(QWebEngineSettings::ShowScrollBars, false);
    this->page()->setBackgroundColor("azure");
    this->load(QUrl("qrc:/web/graph.html"));
}

void GraphView::setGraph(const REDasm::Graphing::Graph &graph)
{
    this->page()->runJavaScript("var graph = new dagre.graphlib.Graph();"
                                "graph.setDefaultEdgeLabel(function() { return { }; });"
                                "graph.setGraph({ });");

    this->generateNodes(graph);
    this->generateEdges(graph);

    this->page()->runJavaScript("d3.selectAll('svg > :not(defs)').remove();"
                                "var svg = d3.select('svg');"
                                "var g = svg.append('g');"
                                "g.call(new dagreD3.render(), graph);" +
                                QString("var mid = (%1 - graph.graph().width) / 2;").arg(this->width()) +
                                QString("g.attr('transform', 'translate(' + mid + ', %1)');").arg(GRAPH_MARGINS) +
                                "svg.call(d3.zoom().on('zoom', function () { "
                                    "g.attr('transform', d3.event.transform);"
                                "}).filter(function() { return d3.event.ctrlKey; }));" +
                                QString("svg.attr('height', '%1');").arg(this->height()) +
                                QString("svg.attr('width', '%1');").arg(this->width()));
}

QColor GraphView::getEdgeColor(const REDasm::Graphing::Node *from, const REDasm::Graphing::Node *to)
{
    Q_UNUSED(from)
    Q_UNUSED(to)

    return QColor(Qt::black);
}

void GraphView::appendCSS(const QString &css)
{
    this->page()->runJavaScript("var css = document.createElement('style');"
                                "css.type = 'text/css';"
                                "document.head.appendChild(css);"
                                "css.innerText = '" + css + "';");
}

void GraphView::initializePage()
{
    QFont font = QFontDatabase::systemFont(QFontDatabase::FixedFont);

    this->page()->runJavaScript("document.designMode = 'on';"
                                "window.ondrop = function() { return false; };"                           // Disable text dragging
                                "window.onkeydown = function(e) { return e.key.startsWith('Arrow'); };"); // Disable character input

    QString generalcss = "html {"
                             "cursor: default;"
                             "font-family:" + font.family() + ";" +
                             "font-size" + QString::number(font.pointSize()) + "pt;" +
                         "}"
                         "html, body {"
                            "overflow: hidden;"
                         "}";

    QString blockcss = ".node rect {"
                           "fill: white;"
                           "stroke: black;"
                           "stroke-width: 2;"
                           "filter: url(#dropshadow);"
                       "}"
                       ".edgePath path {"
                           "stroke-width: 1.5;"
                       "}";

    this->appendCSS(generalcss);
    this->appendCSS(blockcss);
}

void GraphView::generateNodes(const REDasm::Graphing::Graph &graph)
{
    for(auto& n : graph)
    {
        QString content = this->getNodeContent(n.get());
        this->page()->runJavaScript(QString("graph.setNode(%1, { labelType: 'html', "
                                            "                    label: '%2' });").arg(n->id).arg(content));
    }
}

void GraphView::generateEdges(const REDasm::Graphing::Graph &graph)
{
    for(auto& n : graph)
    {
        const REDasm::Graphing::AdjacencyList& edges = graph.edges(n);

        for(auto& e : edges)
        {
            QColor color = this->getEdgeColor(n.get(), e);
            this->page()->runJavaScript(QString("graph.setEdge(%1, %2, { style: 'stroke: %3; fill: transparent', "
                                                                        "arrowheadStyle: 'stroke: %3; fill: %3' });").arg(n->id)
                                                                                                                   .arg(e->id)
                                                                                                                   .arg(color.name()));
        }
    }
}
