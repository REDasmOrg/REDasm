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
    auto& document = m_disassembler->document();
    document->cursor()->moveTo(document->instructionIndex(address));
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
    REDasm::ListingItem currentfunction = r_docnew->functionStart(r_docnew->currentItem().address_new);
    if(!currentfunction.isValid()) return false;

    if(currentfunction.address_new == m_currentfunction.address_new) // Don't render graph again
        return true;

    m_currentfunction = currentfunction;
    auto* graph = r_docnew->graph(currentfunction.address_new);

    if(!graph)
    {
        m_currentfunction = { };
        r_ctx->log("Graph creation failed @ " + REDasm::String::hex(currentfunction.address_new));
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

QColor DisassemblerGraphView::getEdgeColor(const REDasm::Edge& e) const
{
    const REDasm::FunctionBasicBlock* fbb = variant_object<REDasm::FunctionBasicBlock>(this->graph()->data(e.source));
    return THEME_VALUE(Convert::to_qstring(fbb->style(e.target)));
}

REDasm::String DisassemblerGraphView::getEdgeLabel(const REDasm::Edge& e) const
{
    const REDasm::FunctionBasicBlock* fromfbb = variant_object<REDasm::FunctionBasicBlock>(this->graph()->data(e.source));
    const REDasm::FunctionBasicBlock* tofbb = variant_object<REDasm::FunctionBasicBlock>(this->graph()->data(e.target));
    REDasm::ListingDocument& document = m_disassembler->document();
    const REDasm::ListingItem& fromitem = fromfbb->endItem();
    REDasm::CachedInstruction instruction = document->instruction(fromitem.address_new);
    REDasm::String label;

    if(instruction && instruction->typeIs(REDasm::InstructionType::Conditional))
    {
        const REDasm::ListingItem& toitem = tofbb->startItem();

        if(r_disasm->getTarget(instruction->address) == toitem.address_new) label = "TRUE";
        else label = "FALSE";
    }

    if(!(tofbb->startItem().address_new > fromfbb->startItem().address_new))
        label += !label.empty() ? " (LOOP)" : "LOOP";

    return label;
}

GraphViewItem *DisassemblerGraphView::itemFromCurrentLine() const
{
    REDasm::ListingItem item = r_docnew->currentItem();
    if(!item.isValid()) return nullptr;

    if(item.is(REDasm::ListingItemType::FunctionItem)) // Adjust to instruction
        item = r_docnew->itemInstruction(item.address_new);

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
    r_docnew->cursor().disable();
    GraphView::mousePressEvent(e);
}

void DisassemblerGraphView::mouseMoveEvent(QMouseEvent *e)
{
    GraphView::mouseMoveEvent(e);
    GraphViewItem* item = this->selectedItem();
    if(item) r_docnew->cursor().enable();
}
