#include "disassemblergraphview.h"
#include "../../../models/disassemblermodel.h"
#include "../../../redasmsettings.h"
#include "../../../convert.h"
#include <redasm/graph/layout/layeredlayout.h>
#include <redasm/support/utils.h>
#include <redasm/context.h>
#include <QResizeEvent>
#include <QScrollBar>
#include <QPainter>
#include <QAction>

DisassemblerGraphView::DisassemblerGraphView(QWidget *parent): GraphView(parent)
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
    r_evt::ungroup(this);
    this->killTimer(m_blinktimer);
    m_blinktimer = -1;
}

void DisassemblerGraphView::setDisassembler(const REDasm::DisassemblerPtr &disassembler)
{
    GraphView::setDisassembler(disassembler);

    r_evt::subscribe(REDasm::StandardEvents::Cursor_PositionChanged, this, [&](const REDasm::EventArgs*) {
        if(!this->isVisible()) return;
        this->renderGraph();
        if(!this->hasFocus()) this->focusCurrentBlock();
    });
}

bool DisassemblerGraphView::isCursorInGraph() const { return this->itemFromCurrentLine() != nullptr; }

REDasm::String DisassemblerGraphView::currentWord()
{
    if(!this->selectedItem())
        return REDasm::String();

    return static_cast<DisassemblerBlockItem*>(this->selectedItem())->currentWord();
}

void DisassemblerGraphView::computeLayout()
{
    m_disassembleractions->setCurrentRenderer(nullptr);

    this->graph()->nodes().each([&](REDasm::Node n) {
        const REDasm::FunctionBasicBlock* fbb = variant_object<REDasm::FunctionBasicBlock>(this->graph()->data(n));
        auto* dbi = new DisassemblerBlockItem(fbb, m_disassembler, n, this->viewport());
        connect(dbi, &DisassemblerBlockItem::followRequested, this, &DisassemblerGraphView::onFollowRequested);
        connect(dbi, &DisassemblerBlockItem::menuRequested, this, &DisassemblerGraphView::onMenuRequested);

        m_items[n] = dbi;
        this->graph()->width(n, dbi->width());
        this->graph()->height(n, dbi->height());
    });

    this->graph()->edges().each([&](const REDasm::Edge& e) {
        this->graph()->color(e, qUtf8Printable(this->getEdgeColor(e).name()));
        this->graph()->label(e, this->getEdgeLabel(e));
    });

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
    r_doc->cursor().moveTo(r_doc->itemInstructionIndex(address));
    this->renderGraph();
}

void DisassemblerGraphView::focusCurrentBlock()
{
    GraphViewItem* item = this->itemFromCurrentLine();
    if(!item) return;

    this->focusBlock(item);
    this->setSelectedBlock(item);
}

bool DisassemblerGraphView::renderGraph()
{
    REDasm::ListingItem currentfunction = r_doc->functionStart(r_doc->currentItem().address);
    if(!currentfunction.isValid()) return false;

    if(currentfunction.address == m_currentfunction.address) // Don't render graph again
        return true;

    m_currentfunction = currentfunction;
    auto* graph = r_doc->graph(currentfunction.address);

    if(!graph)
    {
        m_currentfunction = { };
        r_ctx->log("Graph creation failed @ " + REDasm::String::hex(currentfunction.address));
        return false;
    }

    this->setGraph(graph);
    return true;
}

void DisassemblerGraphView::mouseReleaseEvent(QMouseEvent *e)
{
    if(e->buttons() == Qt::BackButton) r_doc->cursor().goBack();
    else if(e->buttons() == Qt::ForwardButton) r_doc->cursor().goForward();
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

        if(!this->viewport()->hasFocus() || !item) r_doc->cursor().disable();
        else r_doc->cursor().toggle();

        if(item) item->invalidate();
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

QColor DisassemblerGraphView::getEdgeColor(const REDasm::Edge& e) const
{
    const REDasm::FunctionBasicBlock* fbb = variant_object<REDasm::FunctionBasicBlock>(this->graph()->data(e.source));
    return THEME_VALUE(Convert::to_qstring(fbb->style(e.target)));
}

REDasm::String DisassemblerGraphView::getEdgeLabel(const REDasm::Edge& e) const
{
    const REDasm::FunctionBasicBlock* fromfbb = variant_object<REDasm::FunctionBasicBlock>(this->graph()->data(e.source));
    const REDasm::FunctionBasicBlock* tofbb = variant_object<REDasm::FunctionBasicBlock>(this->graph()->data(e.target));
    const REDasm::ListingItem& fromitem = fromfbb->endItem();
    REDasm::CachedInstruction instruction = r_doc->instruction(fromitem.address);
    REDasm::String label;

    if(instruction && instruction->isConditional())
    {
        const REDasm::ListingItem& toitem = tofbb->startItem();

        if(r_disasm->getTarget(instruction->address) == toitem.address) label = "TRUE";
        else label = "FALSE";
    }

    if(!(tofbb->startItem().address > fromfbb->startItem().address))
        label += !label.empty() ? " (LOOP)" : "LOOP";

    return label;
}

GraphViewItem *DisassemblerGraphView::itemFromCurrentLine() const
{
    REDasm::ListingItem item = r_doc->currentItem();
    if(!item.isValid()) return nullptr;

    if(item.is(REDasm::ListingItem::FunctionItem)) // Adjust to instruction
        item = r_doc->itemInstruction(item.address);

    for(const auto& gvi : m_items)
    {
        DisassemblerBlockItem* dbi = static_cast<DisassemblerBlockItem*>(gvi);
        if(!dbi->containsItem(item)) continue;
        return gvi;
    }

    return nullptr;
}

void DisassemblerGraphView::mousePressEvent(QMouseEvent *e)
{
    r_doc->cursor().disable();
    GraphView::mousePressEvent(e);
}

void DisassemblerGraphView::mouseMoveEvent(QMouseEvent *e)
{
    GraphView::mouseMoveEvent(e);
    GraphViewItem* item = this->selectedItem();
    if(item) r_doc->cursor().enable();
}
