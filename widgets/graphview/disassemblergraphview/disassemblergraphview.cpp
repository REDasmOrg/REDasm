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
    this->setFocusPolicy(Qt::StrongFocus);
    m_blinktimer = this->startTimer(CURSOR_BLINK_INTERVAL);
}

DisassemblerGraphView::~DisassemblerGraphView()
{
    this->killTimer(m_blinktimer);
    m_blinktimer = -1;
}

void DisassemblerGraphView::computeLayout()
{
    for(const auto& n : this->graph()->nodes())
    {
        const auto* fbb = static_cast<REDasm::Graphing::FunctionGraph*>(this->graph())->data(n);
        auto* dbi = new DisassemblerBlockItem(fbb, m_disassembler, n, this->viewport());

        connect(dbi->disassemblerActions(), &DisassemblerActions::gotoDialogRequested, this, &DisassemblerGraphView::gotoDialogRequested);
        connect(dbi->disassemblerActions(), &DisassemblerActions::hexDumpRequested, this, &DisassemblerGraphView::hexDumpRequested);
        connect(dbi->disassemblerActions(), &DisassemblerActions::referencesRequested, this, &DisassemblerGraphView::referencesRequested);
        connect(dbi->disassemblerActions(), &DisassemblerActions::switchToHexDump, this, &DisassemblerGraphView::switchToHexDump);
        connect(dbi->disassemblerActions(), &DisassemblerActions::callGraphRequested, this, &DisassemblerGraphView::callGraphRequested);

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
}

void DisassemblerGraphView::goTo(address_t address)
{
    auto& document = m_disassembler->document();
    document->cursor()->moveTo(document->instructionIndex(address));
    this->renderGraph();
}

void DisassemblerGraphView::focusCurrentBlock()
{
    const REDasm::ListingCursor* cursor = m_disassembler->document()->cursor();

    for(const auto& item : m_items)
    {
        if(!static_cast<DisassemblerBlockItem*>(item)->hasIndex(cursor->currentLine()))
            continue;

        this->focusBlock(item);
        break;
    }
}

bool DisassemblerGraphView::renderGraph()
{
    auto& document = m_disassembler->document();
    REDasm::ListingItem* currentfunction = document->functionStart(document->currentItem());

    if(!currentfunction)
        return false;

    if(m_currentfunction && (m_currentfunction == currentfunction))
        return true;

    m_currentfunction = currentfunction;

    const REDasm::ListingItem* currentitem = document->currentItem();
    auto graph = std::make_unique<REDasm::Graphing::FunctionGraph>(m_disassembler.get());

    if(!graph->build(currentitem->address))
    {
        REDasm::log("Graph creation failed @ " + REDasm::hex(currentitem->address));
        return false;
    }

    this->setGraph(graph.release());
    return true;
}

void DisassemblerGraphView::mouseReleaseEvent(QMouseEvent *e)
{
    if(e->button() == Qt::BackButton)
        m_disassembler->document()->cursor()->goBack();
    else if(e->button() == Qt::ForwardButton)
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

    if(instruction && instruction->is(REDasm::InstructionTypes::Conditional))
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
