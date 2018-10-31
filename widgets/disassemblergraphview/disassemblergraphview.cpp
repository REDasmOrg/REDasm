#include "disassemblergraphview.h"
#include "../../redasm/disassembler/graph/functiongraph.h"
#include "../../renderer/listinggraphrenderer.h"
#include "../../themeprovider.h"
#include <QTextDocument>

DisassemblerGraphView::DisassemblerGraphView(QWidget *parent): GraphView(parent), m_disassembler(NULL), m_currentfunction(NULL)
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

    connect(m_graphwebchannel, &DisassemblerWebChannel::addressChanged, this, &DisassemblerGraphView::updateGraph);
    connect(m_graphwebchannel, &DisassemblerWebChannel::addressChanged, this, &DisassemblerGraphView::addressChanged);
    connect(m_graphwebchannel, &DisassemblerWebChannel::referencesRequested, this, &DisassemblerGraphView::referencesRequested);
    connect(m_graphwebchannel, &DisassemblerWebChannel::switchView, this, &DisassemblerGraphView::switchView);
}

void DisassemblerGraphView::goTo(address_t address)
{
    REDasm::ListingDocument* doc = m_disassembler->document();
    doc->cursor()->moveTo(doc->instructionIndex(address));
    this->graph();
}

void DisassemblerGraphView::graph()
{
    REDasm::ListingDocument* doc = m_disassembler->document();
    REDasm::ListingItem* currentfunction = doc->functionStart(doc->currentItem());

    if(m_currentfunction && (m_currentfunction == currentfunction))
        return;

    m_currentfunction = currentfunction;

    REDasm::Graphing::FunctionGraph graph(doc);
    graph.build(doc->currentItem()->address);

    this->setGraph(graph);
    this->zoomOn(doc->cursor()->currentLine());
}

QString DisassemblerGraphView::getNodeTitle(const REDasm::Graphing::Node *n) const
{
    const REDasm::Graphing::FunctionBlock* fb = static_cast<const REDasm::Graphing::FunctionBlock*>(n);
    REDasm::ListingDocument* doc = m_disassembler->document();
    REDasm::ListingItem* item = doc->itemAt(fb->startidx);
    REDasm::SymbolPtr symbol = doc->symbol(item->address);

    if(!symbol)
        return "Condition FALSE";

    if(symbol->isFunction())
        return QString::fromStdString(symbol->name);

    REDasm::ReferenceVector refs = m_disassembler->getReferences(symbol->address);

    if(refs.size() > 1)
        return QString("From %1 blocks").arg(refs.size());

    REDasm::InstructionPtr instruction = doc->instruction(refs.front());

    if(instruction->is(REDasm::InstructionTypes::Conditional))
    {
        if(instruction->target() == item->address)
            return "Condition TRUE";

        return "Condition FALSE";
    }

    return "Unconditional";
}

QString DisassemblerGraphView::getNodeContent(const REDasm::Graphing::Node *n) const
{
    const REDasm::Graphing::FunctionBlock* fb = static_cast<const REDasm::Graphing::FunctionBlock*>(n);
    ListingGraphRenderer lgr(m_disassembler);

    QTextDocument textdocument;
    lgr.render(fb->startidx, fb->count(), &textdocument);
    return textdocument.toPlainText();
}

QColor DisassemblerGraphView::getEdgeColor(const REDasm::Graphing::Node *from, const REDasm::Graphing::Node *to) const
{
    const REDasm::Graphing::FunctionBlock* fb = static_cast<const REDasm::Graphing::FunctionBlock*>(from);
    return QColor(QString::fromStdString(fb->color(static_cast<const REDasm::Graphing::FunctionBlock*>(to))));
}

void DisassemblerGraphView::initializePage()
{
    GraphView::initializePage();

    this->appendCSS(QString(".highlight { background-color: %1; }"
                            ".seek { color: %2; background-color: %3; }").arg(THEME_VALUE_COLOR("highlight_fg"))
                                                                         .arg(THEME_VALUE_COLOR("highlight_bg"))
                                                                         .arg(THEME_VALUE_COLOR("seek")));

    this->page()->runJavaScript("document.addEventListener('keydown', function(e) {"
                                    "if(e.code === 'Space')"
                                        "channelobjects.graphchannel.switchToListing();"
                                    "else if(e.key === 'x')"
                                        "channelobjects.graphchannel.showReferencesUnderCursor();"
                                "});");

    this->page()->runJavaScript("document.addEventListener('dblclick', function(e) {"
                                    "if(e.button === 0)" // Left button
                                        "channelobjects.graphchannel.followUnderCursor();"
                                "});");

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
                                    "channelobjects.graphchannel.moveTo(e.target.dataset.line, e.target.innerText);"
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

void DisassemblerGraphView::updateGraph()
{
    if(!this->isVisible())
        return;

    this->graph();
}
