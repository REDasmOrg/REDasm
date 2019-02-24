#include "disassemblergraphview.h"
#include "../../renderer/listinggraphrenderer.h"
#include "../../themeprovider.h"
#include <redasm/disassembler/graph/functiongraph.h>
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
    auto& document = m_disassembler->document();
    document->cursor()->moveTo(document->instructionIndex(address));
    this->graph();
}

bool DisassemblerGraphView::graph()
{
    auto& document = m_disassembler->document();
    REDasm::ListingItem* currentfunction = document->functionStart(document->currentItem());

    if(!currentfunction)
        return false;

    if(m_currentfunction && (m_currentfunction == currentfunction))
        return true;

    m_currentfunction = currentfunction;

    REDasm::ListingItem* currentitem = document->currentItem();
    REDasm::Graphing::FunctionGraph graph(document);

    if(!graph.build(currentitem->address))
    {
        address_location address = graph.startAddress();
        REDasm::log("Graph creation failed @ " + REDasm::hex(address.valid ? address : currentitem->address));
        return false;
    }

    this->setGraph(graph);
    this->zoomOn(document->cursor()->currentLine());
    return true;
}

QString DisassemblerGraphView::getNodeTitle(const REDasm::Graphing::Node *n) const
{
    const REDasm::Graphing::FunctionBlock* fb = static_cast<const REDasm::Graphing::FunctionBlock*>(n);
    REDasm::ListingDocument& document = m_disassembler->document();
    REDasm::ListingItem* item = document->itemAt(fb->startidx);
    REDasm::SymbolPtr symbol = document->symbol(item->address);

    if(!symbol)
        return "Condition FALSE";

    if(symbol->isFunction())
        return QString::fromStdString(symbol->name);

    REDasm::ReferenceVector refs = m_disassembler->getReferences(symbol->address);

    if(refs.size() > 1)
        return QString("From %1 blocks").arg(refs.size());

    REDasm::InstructionPtr instruction = document->instruction(refs.front());

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

    this->appendCSS(QString(".highlight { background-color: %1; color: %2 }"
                            ".seek { background-color: %3; }").arg(THEME_VALUE_COLOR("highlight_bg"))
                                                              .arg(THEME_VALUE_COLOR("highlight_fg"))
                                                              .arg(THEME_VALUE_COLOR("seek")));
}

void DisassemblerGraphView::updateGraph()
{
    if(!this->isVisible())
        return;

    this->graph();
}
