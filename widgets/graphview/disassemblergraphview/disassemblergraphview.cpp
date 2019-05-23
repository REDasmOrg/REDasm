#include "disassemblergraphview.h"
#include "../../../models/disassemblermodel.h"
#include "../../../redasmsettings.h"
#include <redasm/graph/layout/layeredlayout.h>
#include <QResizeEvent>
#include <QScrollBar>
#include <QPainter>
#include <QDebug>
#include <QAction>

DisassemblerGraphView::DisassemblerGraphView(QWidget *parent): GraphView(parent), m_currentfunction(nullptr)
{
    m_blinktimer = this->startTimer(CURSOR_BLINK_INTERVAL);
    this->setFocusPolicy(Qt::StrongFocus);

    m_disassembleractions = new DisassemblerActions(this);
    connect(m_disassembleractions, &DisassemblerActions::gotoDialogRequested, this, &DisassemblerGraphView::gotoDialogRequested);
    connect(m_disassembleractions, &DisassemblerActions::hexDumpRequested, this, &DisassemblerGraphView::hexDumpRequested);
    connect(m_disassembleractions, &DisassemblerActions::referencesRequested, this, &DisassemblerGraphView::referencesRequested);
    connect(m_disassembleractions, &DisassemblerActions::switchToHexDump, this, &DisassemblerGraphView::switchToHexDump);
    connect(m_disassembleractions, &DisassemblerActions::callGraphRequested, this, &DisassemblerGraphView::callGraphRequested);
    connect(m_disassembleractions, &DisassemblerActions::itemInformationRequested, this, &DisassemblerGraphView::itemInformationRequested);
}

DisassemblerGraphView::~DisassemblerGraphView()
{
    EVENT_DISCONNECT(m_disassembler->document()->cursor(), positionChanged, this);

    this->killTimer(m_blinktimer);
    m_blinktimer = -1;
}

void DisassemblerGraphView::setDisassembler(const REDasm::DisassemblerPtr &disassembler)
{
    GraphView::setDisassembler(disassembler);

    EVENT_CONNECT(m_disassembler->document()->cursor(), positionChanged, this, [&]() {
        if(!this->isVisible())
            return;

        this->renderGraph();

        if(!this->hasFocus())
            this->focusCurrentBlock();
    });
}

bool DisassemblerGraphView::isCursorInGraph() const { return this->itemFromCurrentLine() != nullptr; }

std::string DisassemblerGraphView::currentWord()
{
    if(!this->selectedItem())
        return std::string();

    return static_cast<DisassemblerBlockItem*>(this->selectedItem())->currentWord();
}

void DisassemblerGraphView::computeLayout()
{
    m_disassembleractions->setCurrentRenderer(nullptr);

    for(const auto& n : this->graph()->nodes())
    {
        const auto* fbb = static_cast<const REDasm::Graphing::FunctionGraph*>(this->graph())->data(n);
        auto* dbi = new DisassemblerBlockItem(fbb, m_disassembler, n, this->viewport());
        connect(dbi, &DisassemblerBlockItem::followRequested, this, &DisassemblerGraphView::onFollowRequested);
        connect(dbi, &DisassemblerBlockItem::menuRequested, this, &DisassemblerGraphView::onMenuRequested);

        m_items[n] = dbi;
        this->graph()->width(n, dbi->width());
        this->graph()->height(n, dbi->height());
    }

    for(const auto& e : this->graph()->edges())
    {
        this->graph()->color(e, this->getEdgeColor(e).name().toStdString());
        this->graph()->label(e, this->getEdgeLabel(e));
    }

    REDasm::Graphing::LayeredLayout ll(this->graph());
    ll.execute();

    GraphView::computeLayout();
    this->focusCurrentBlock();
}

void DisassemblerGraphView::onFollowRequested(const QPointF& localpos)
{
    if(!m_disassembleractions->renderer())
        return;

    if(!m_disassembleractions->followUnderCursor())
        static_cast<ListingRendererCommon*>(m_disassembleractions->renderer())->selectWordAt(localpos);
    else
        this->focusCurrentBlock();
}

void DisassemblerGraphView::onMenuRequested()
{
    if(!m_disassembleractions->renderer())
        return;

    m_disassembleractions->popup(QCursor::pos());
}

void DisassemblerGraphView::goTo(address_t address)
{
    auto& document = m_disassembler->document();
    document->cursor()->moveTo(document->instructionIndex(address));
    this->renderGraph();
}

void DisassemblerGraphView::focusCurrentBlock()
{
    GraphViewItem* item = this->itemFromCurrentLine();

    if(!item)
        return;

    this->focusBlock(item);
    this->setSelectedBlock(item);
}

bool DisassemblerGraphView::renderGraph()
{
    auto& document = m_disassembler->document();
    const REDasm::ListingItem* currentfunction = document->functionStart(document->currentItem());

    if(!currentfunction)
        return false;

    if(currentfunction == m_currentfunction) // Don't render graph again
        return true;

    m_currentfunction = currentfunction;
    auto* graph = document->functions().graph(currentfunction);

    if(!graph)
    {
        REDasm::log("Graph creation failed @ " + REDasm::hex(currentfunction->address));
        return false;
    }

    this->setGraph(graph);
    return true;
}

void DisassemblerGraphView::mouseReleaseEvent(QMouseEvent *e)
{
    if(e->buttons() == Qt::BackButton)
        m_disassembler->document()->cursor()->goBack();
    else if(e->buttons() == Qt::ForwardButton)
        m_disassembler->document()->cursor()->goForward();

    GraphView::mouseReleaseEvent(e);
}

void DisassemblerGraphView::keyPressEvent(QKeyEvent *e)
{
    if(e->key() == Qt::Key_Space)
        emit switchView();

    return GraphView::keyPressEvent(e);
}

void DisassemblerGraphView::showEvent(QShowEvent *e)
{
    GraphView::showEvent(e);
    this->focusCurrentBlock();
}

void DisassemblerGraphView::timerEvent(QTimerEvent *e)
{
    if(!m_disassembler->busy() && this->isVisible() && (e->timerId() == m_blinktimer))
    {
        GraphViewItem* item = this->selectedItem();

        if(!this->viewport()->hasFocus() || !item)
            m_disassembler->document()->cursor()->disable();
        else
            m_disassembler->document()->cursor()->toggle();

        if(item)
            item->invalidate();
    }

    GraphView::timerEvent(e);
}

void DisassemblerGraphView::selectedItemChangedEvent()
{
    GraphViewItem* selecteditem = this->selectedItem();

    if(selecteditem)
        m_disassembleractions->setCurrentRenderer(static_cast<DisassemblerBlockItem*>(selecteditem)->renderer());
    else
        m_disassembleractions->setCurrentRenderer(nullptr);

    GraphView::selectedItemChangedEvent();
}

QColor DisassemblerGraphView::getEdgeColor(const REDasm::Graphing::Edge &e) const
{
    const REDasm::Graphing::FunctionBasicBlock* fbb = static_cast<const REDasm::Graphing::FunctionGraph*>(this->graph())->data(e.source);
    return THEME_VALUE(QString::fromStdString(fbb->style(e.target)));
}

std::string DisassemblerGraphView::getEdgeLabel(const REDasm::Graphing::Edge &e) const
{
    const REDasm::Graphing::FunctionBasicBlock* fromfbb = static_cast<const REDasm::Graphing::FunctionGraph*>(this->graph())->data(e.source);
    const REDasm::Graphing::FunctionBasicBlock* tofbb = static_cast<const REDasm::Graphing::FunctionGraph*>(this->graph())->data(e.target);
    REDasm::ListingDocument& document = m_disassembler->document();
    const REDasm::ListingItem* fromitem = document->itemAt(fromfbb->endidx);
    REDasm::InstructionPtr instruction = document->instruction(fromitem->address);
    std::string label;

    if(instruction && instruction->is(REDasm::InstructionType::Conditional))
    {
        const REDasm::ListingItem* toitem = document->itemAt(tofbb->startidx);

        if(m_disassembler->getTarget(instruction->address) == toitem->address)
            label = "TRUE";
        else
            label = "FALSE";
    }

    if(tofbb->startidx <= fromfbb->startidx)
        label += !label.empty() ? " (LOOP)" : "LOOP";

    return label;
}

GraphViewItem *DisassemblerGraphView::itemFromCurrentLine() const
{
    const REDasm::ListingCursor* cursor = m_disassembler->document()->cursor();
    const REDasm::ListingItem* item = m_disassembler->document()->currentItem();

    if(!item)
        return nullptr;

    size_t line = cursor->currentLine();

    if(item->is(REDasm::ListingItem::FunctionItem)) // Adjust to instruction
        line = m_disassembler->document()->instructionIndex(item->address);

    for(const auto& item : m_items)
    {
        DisassemblerBlockItem* dbi = static_cast<DisassemblerBlockItem*>(item);

        if(!dbi->containsIndex(line))
            continue;

        return item;
    }

    return nullptr;
}

void DisassemblerGraphView::mousePressEvent(QMouseEvent *e)
{
    m_disassembler->document()->cursor()->disable();
    GraphView::mousePressEvent(e);
}

void DisassemblerGraphView::mouseMoveEvent(QMouseEvent *e)
{
    GraphView::mouseMoveEvent(e);
    GraphViewItem* item = this->selectedItem();

    if(item)
        m_disassembler->document()->cursor()->enable();
}
