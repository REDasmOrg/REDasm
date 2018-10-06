#include "disassemblergraphview.h"
#include "../../redasm/disassembler/graph/functiongraph.h"
#include "../../renderer/listinggraphrenderer.h"
#include "../../themeprovider.h"
#include <QTextDocument>

DisassemblerGraphView::DisassemblerGraphView(QWidget *parent): GraphView(parent), m_disassembler(NULL)
{
    m_webchannel = new QWebChannel(this);

    this->page()->setWebChannel(m_webchannel);
    this->page()->setBackgroundColor(THEME_VALUE("graph_bg"));
}

void DisassemblerGraphView::setDisassembler(REDasm::DisassemblerAPI *disassembler)
{
    m_disassembler = disassembler;

    m_graphwebchannel = new DisassemblerWebChannel(disassembler, this);
    m_webchannel->registerObject("graphchannel", m_graphwebchannel);
}

void DisassemblerGraphView::graph()
{
    REDasm::ListingDocument* doc = m_disassembler->document();
    REDasm::Graphing::FunctionGraph graph(doc);
    graph.build(doc->currentItem()->address);
    this->setGraph(graph);
}

QString DisassemblerGraphView::getNodeContent(const REDasm::Graphing::Node *n)
{
    const REDasm::Graphing::FunctionBlock* fb = static_cast<const REDasm::Graphing::FunctionBlock*>(n);
    ListingGraphRenderer lgr(m_disassembler);

    QTextDocument textdocument;
    lgr.render(fb->startidx, fb->count(), &textdocument);
    return textdocument.toPlainText();
}

QColor DisassemblerGraphView::getEdgeColor(const REDasm::Graphing::Node *from, const REDasm::Graphing::Node *to)
{
    const REDasm::Graphing::FunctionBlock* fb = static_cast<const REDasm::Graphing::FunctionBlock*>(from);
    return QColor(QString::fromStdString(fb->color(static_cast<const REDasm::Graphing::FunctionBlock*>(to))));
}

void DisassemblerGraphView::initializePage()
{
    GraphView::initializePage();

    this->appendCSS(QString(".highlight { background-color: %1; }"
                            ".seek { background-color: %2; }").arg(THEME_VALUE_COLOR("highlight")).arg(THEME_VALUE_COLOR("seek")));

    this->page()->runJavaScript("document.addEventListener('click', function(e) {"
                                    "let line = document.querySelector('.seek');"
                                    "if(line)"
                                        "line.classList.remove('seek');"
                                    "line = e.target;"
                                    "while(line && !('lineroot' in line.dataset))"
                                        "line = line.parentElement;"
                                    "if(line)"
                                        "line.classList.add('seek');"
                                "});");

    this->page()->runJavaScript("document.addEventListener('click', function(e) {"
                                    "if(!('line' in e.target.dataset))"
                                        "return;"
                                    "channelobjects.graphchannel.updateLine(e.target.dataset.line);"
                                "});");

    this->page()->runJavaScript("document.addEventListener('click', function(e) {"
                                    "let oldhighlight = document.querySelectorAll('.highlight');"               // Remove old highlighting (1)
                                    "oldhighlight.forEach(function(e) { e.classList.remove('highlight'); });"   // Remove old highlighting (2)
                                    "if(e.target.tagName !== 'SPAN')"
                                        "return;"
                                    "let word = e.target.innerText;"
                                    "let query = '//span[text()=\"' + word + '\"]';"
                                    "let xhl = document.evaluate(query, document, null, XPathResult.ORDERED_NODE_SNAPSHOT_TYPE);" // Find all spans
                                    "for(let i = 0; i < xhl.snapshotLength; i++)"
                                        "xhl.snapshotItem(i).classList.add('highlight');"                       // Apply highlighting
                                "});");
}
