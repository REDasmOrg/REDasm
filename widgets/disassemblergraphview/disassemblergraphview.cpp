#include "disassemblergraphview.h"
#include "../../renderer/listinggraphrenderer.h"
#include "../../models/disassemblermodel.h"
#include "../../themeprovider.h"
#include <redasm/disassembler/graph/functiongraph.h>
#include <QTextDocument>
#include <QKeySequence>
#include <QAction>
#include <QHelpEvent>

DisassemblerGraphView::DisassemblerGraphView(QWidget *parent): GraphView(parent), m_disassembler(NULL), m_currentfunction(NULL)
{
    m_webchannel = new QWebChannel(this);

    this->page()->setWebChannel(m_webchannel);
    this->page()->setBackgroundColor(THEME_VALUE("graph_bg"));
    this->focusProxy()->installEventFilter(this);
}

void DisassemblerGraphView::setDisassembler(REDasm::DisassemblerAPI *disassembler)
{
    m_disassembler = disassembler;

    EVENT_CONNECT(m_disassembler->document()->cursor(), positionChanged, this, [&]() { this->updateGraph(); });

    m_graphwebchannel = new DisassemblerWebChannel(disassembler, this);
    m_webchannel->registerObject("graphchannel", m_graphwebchannel);

    connect(m_contextmenu, &QMenu::aboutToShow, this, &DisassemblerGraphView::adjustActions);

    connect(m_graphwebchannel, &DisassemblerWebChannel::referencesRequested, this, &DisassemblerGraphView::referencesRequested);
    connect(m_graphwebchannel, &DisassemblerWebChannel::switchView, this, &DisassemblerGraphView::switchView);

    connect(m_graphwebchannel, &DisassemblerWebChannel::redrawGraph, this, [&]() {
        m_currentfunction = nullptr;
        this->graph();
    });
}

bool DisassemblerGraphView::eventFilter(QObject *obj, QEvent *e)
{
    if (e->type() == QEvent::KeyPress)
    {
        QKeyEvent* keyEvent = static_cast<QKeyEvent*>(e);
        this->keyPressEvent(keyEvent);
    }
    else if (e->type() == QEvent::MouseButtonPress)
    {
        QMouseEvent* mouseEvent = static_cast<QMouseEvent*>(e);
        this->mousePressEvent(mouseEvent);
    }

    return QWebEngineView::eventFilter(obj, e);
}

void DisassemblerGraphView::keyPressEvent(QKeyEvent *e)
{
    if (e->key() == Qt::Key_Space)
        m_graphwebchannel->switchToListing();
    else if (e->key() == Qt::Key_X)
        m_graphwebchannel->showReferencesUnderCursor();
    else if (e->key() == Qt::Key_N)
        m_graphwebchannel->renameUnderCursor();
}

void DisassemblerGraphView::mousePressEvent(QMouseEvent *e)
{
    if (e->buttons() == Qt::BackButton)
        this->goBack();
    else if (e->buttons() == Qt::ForwardButton)
        this->goForward();
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
    REDasm::Graphing::FunctionGraph graph(m_disassembler);

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

QString DisassemblerGraphView::getNodeContent(const REDasm::Graphing::Node *n) const
{
    const REDasm::Graphing::FunctionBasicBlock* fbb = static_cast<const REDasm::Graphing::FunctionBasicBlock*>(n);
    ListingGraphRenderer lgr(m_disassembler);

    QTextDocument textdocument;
    lgr.render(fbb->startidx, fbb->count(), &textdocument);
    return textdocument.toPlainText();
}

QColor DisassemblerGraphView::getEdgeColor(const REDasm::Graphing::Node *from, const REDasm::Graphing::Node *to) const
{
    const REDasm::Graphing::FunctionBasicBlock* fbb = static_cast<const REDasm::Graphing::FunctionBasicBlock*>(from);
    return THEME_VALUE(QString::fromStdString(fbb->style(static_cast<const REDasm::Graphing::FunctionBasicBlock*>(to))));
}

QString DisassemblerGraphView::getEdgeLabel(const REDasm::Graphing::Node *from, const REDasm::Graphing::Node *to) const
{
    const REDasm::Graphing::FunctionBasicBlock* fromfbb = static_cast<const REDasm::Graphing::FunctionBasicBlock*>(from);
    const REDasm::Graphing::FunctionBasicBlock* tofbb = static_cast<const REDasm::Graphing::FunctionBasicBlock*>(to);
    REDasm::ListingDocument& document = m_disassembler->document();
    const REDasm::ListingItem* fromitem = document->itemAt(fromfbb->endidx);
    REDasm::InstructionPtr instruction = document->instruction(fromitem->address);
    QString label;

    if(instruction && instruction->is(REDasm::InstructionTypes::Conditional))
    {
        const REDasm::ListingItem* toitem = document->itemAt(tofbb->startidx);

        if(m_disassembler->getTarget(instruction->address) == toitem->address)
            label = "TRUE";
        else
            label = "FALSE";
    }

    if(tofbb->startidx <= fromfbb->startidx)
        label += !label.isEmpty() ? " (LOOP)" : "LOOP";

    return label;
}

void DisassemblerGraphView::initializePage()
{
    GraphView::initializePage();

    this->appendCSS(QString(".highlight { background-color: %1; color: %2 }"
                            ".seek { background-color: %3; }").arg(THEME_VALUE_COLOR("highlight_bg"))
                                                              .arg(THEME_VALUE_COLOR("highlight_fg"))
                                                              .arg(THEME_VALUE_COLOR("seek")));
}

void DisassemblerGraphView::configureActions()
{
    m_actrename = m_contextmenu->addAction("Rename", m_graphwebchannel, &DisassemblerWebChannel::renameUnderCursor, QKeySequence(Qt::Key_N));
    m_contextmenu->addSeparator();
    m_actxrefs = m_contextmenu->addAction("Cross References", m_graphwebchannel, &DisassemblerWebChannel::showReferencesUnderCursor, QKeySequence(Qt::Key_X));
    m_actfollow = m_contextmenu->addAction("Follow", m_graphwebchannel, &DisassemblerWebChannel::followUnderCursor);
    m_actcallgraph = m_contextmenu->addAction("Call Graph", this, &DisassemblerGraphView::showCallGraph);
    m_contextmenu->addSeparator();
    m_acthexdump = m_contextmenu->addAction("Hex Dump Function", this, &DisassemblerGraphView::printFunctionHexDump);
    m_contextmenu->addSeparator();
    m_actback = m_contextmenu->addAction("Back", this, &DisassemblerGraphView::goBack, QKeySequence(Qt::CTRL + Qt::Key_Left));
    m_actforward = m_contextmenu->addAction("Forward", this, &DisassemblerGraphView::goForward, QKeySequence(Qt::CTRL + Qt::Key_Right));
    m_contextmenu->addSeparator();

    GraphView::configureActions();
}

void DisassemblerGraphView::updateGraph()
{
    if(!m_disassembler || m_disassembler->busy() || !this->isVisible())
        return;

    if(m_currentfunction == m_disassembler->document()->currentFunction())
        this->focusOnLine(m_disassembler->document()->cursor()->currentLine());
    else
        this->graph();
}

void DisassemblerGraphView::adjustActions()
{
    REDasm::ListingDocument& document = m_disassembler->document();
    REDasm::ListingItem* item = document->currentItem();

    if(!item)
        return;

    const REDasm::Symbol* symbol = document->symbol(document->cursor()->wordUnderCursor());

    if(!symbol)
    {
        const REDasm::Segment* symbolsegment = document->segment(item->address);

        m_actfollow->setVisible(false);
        m_actxrefs->setVisible(false);
        m_actrename->setVisible(false);

        symbol = document->functionStartSymbol(document->currentItem()->address);

        if(symbol)
            m_actcallgraph->setText(QString("Callgraph %1").arg(S_TO_QS(symbol->name)));

        m_actcallgraph->setVisible(symbol && symbolsegment && symbolsegment->is(REDasm::SegmentTypes::Code));
        m_acthexdump->setVisible((symbol != nullptr));
        return;
    }

    m_actfollow->setText(QString("Follow %1").arg(S_TO_QS(symbol->name)));
    m_actfollow->setVisible(symbol->is(REDasm::SymbolTypes::Code));

    m_actxrefs->setText(QString("Cross Reference %1").arg(S_TO_QS(symbol->name)));
    m_actxrefs->setVisible(true);

    m_actrename->setText(QString("Rename %1").arg(S_TO_QS(symbol->name)));
    m_actrename->setVisible(!symbol->isLocked());

    m_actcallgraph->setVisible(symbol->isFunction());
    m_actcallgraph->setText(QString("Callgraph %1").arg(S_TO_QS(symbol->name)));
}

void DisassemblerGraphView::showCallGraph()
{
    REDasm::ListingDocument& document = m_disassembler->document();
    const REDasm::Symbol* symbol = document->symbol(document->cursor()->wordUnderCursor());

    if(!symbol)
    {
        REDasm::ListingItem* item = document->currentItem();
        symbol = document->functionStartSymbol(item->address);
    }

    emit callGraphRequested(symbol->address);
}

void DisassemblerGraphView::printFunctionHexDump()
{
    const REDasm::Symbol* symbol = nullptr;
    std::string s = m_disassembler->getHexDump(m_disassembler->document()->currentItem()->address, &symbol);

    if(s.empty())
        return;

    REDasm::log(symbol->name + ":" + REDasm::quoted(s));
}

void DisassemblerGraphView::goBack() { m_disassembler->document()->cursor()->goBack(); }
void DisassemblerGraphView::goForward() { m_disassembler->document()->cursor()->goForward(); }
