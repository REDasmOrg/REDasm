#include "graphview.h"
#include <QWebEngineSettings>
#include <QFontDatabase>
#include "../../themeprovider.h"

#define GRAPH_MARGINS 20

GraphView::GraphView(QWidget *parent): QWebEngineView(parent)
{
    connect(this, &GraphView::loadFinished, this, &GraphView::initializePage);

    this->settings()->setAttribute(QWebEngineSettings::ShowScrollBars, false);
    this->load(QUrl("qrc:/web/graph.html"));
}

void GraphView::setGraph(const REDasm::Graphing::Graph &graph)
{
    this->page()->runJavaScript("var graph = new dagre.graphlib.Graph();"
                                "graph.setDefaultEdgeLabel(function() { return { }; });"
                                "graph.setGraph({ });");

    this->generateNodes(graph);
    this->generateEdges(graph);

    this->page()->runJavaScript("dagre.layout(graph, { acyclier: 'greedy' });"
                                "d3.selectAll('svg > :not(defs)').remove();"
                                "var svg = d3.select('svg');"
                                "var g = svg.append('g');"
                                "var zoom = d3.zoom().on('zoom', function() { g.attr('transform', d3.event.transform); });"
                                "g.call(new dagreD3.render(), graph);" +
                                QString("var mid = (%1 - graph.graph().width) / 2;").arg(this->width()) +
                                QString("g.attr('transform', 'translate(' + mid + ', %1)');").arg(GRAPH_MARGINS) +
                                "svg.call(zoom.filter(function() { return d3.event.ctrlKey; }));" +
                                QString("svg.attr('height', '%1');").arg(this->height()) +
                                QString("svg.attr('width', '%1');").arg(this->width()));
}

QString GraphView::getNodeTitle(const REDasm::Graphing::Node *n) const { Q_UNUSED(n) return QString(); }

QColor GraphView::getEdgeColor(const REDasm::Graphing::Node *from, const REDasm::Graphing::Node *to) const
{
    Q_UNUSED(from)
    Q_UNUSED(to)

    return QColor(Qt::black);
}

void GraphView::zoomOn(int line)
{
    /*
    this->page()->runJavaScript(QString("var n = d3.select('div[data-lineroot][data-line=\"%1\"]').node();").arg(line) +
                                QString("console.log('div[data-lineroot][data-line=\"%1\"]');").arg(line) +
                                "while(n && !n.classList.contains('label'))"
                                    "n = n.parentElement;"
                                "if(n) {"
                                    "var zoomscale = 2.0;"
                                    "var bb = n.getBBox();"
                                    "var s = d3.select(n);"
                                "}");
    */
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
                             "font-size:" + QString::number(font.pointSize()) + "pt;" +
                         "}"
                         "html, body {"
                            "overflow: hidden;"
                         "}";

    QString blockcss =  ".nodetitle { "
                            "text-align: center;"
                            "margin-bottom: 4px;"
                            "border: 1px solid " + THEME_VALUE_COLOR("text_fg") + ";"
                            "background-color: " + THEME_VALUE_COLOR("seek") + ";"
                            "color: " + THEME_VALUE_COLOR("text_fg") + ";"
                        "}"
                         ".node rect {"
                            "fill: white;"
                            "stroke: black;"
                            "stroke-width: 3;"
                            "filter: url(#dropshadow);"
                        "}"
                        ".edgePath path {"
                            "stroke-width: 1.5;"
                        "}";

    this->appendCSS(generalcss);
    this->appendCSS(blockcss);
}

QString GraphView::nodeTitle(const REDasm::Graphing::Node *n) const
{
    QString titlecontent = this->getNodeTitle(n);

    if(titlecontent.isEmpty())
        return QString();

    return QString("<div contenteditable=\"false\" class=\"nodetitle\">%1</div>").arg(titlecontent);
}

void GraphView::generateNodes(const REDasm::Graphing::Graph &graph)
{
    for(auto& n : graph)
    {
        QString title = this->nodeTitle(n.get()), content = this->getNodeContent(n.get());

        this->page()->runJavaScript(QString("graph.setNode(%1, { labelType: 'html', "
                                            "                    label: '%2%3' });").arg(n->id).arg(title, content));
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
