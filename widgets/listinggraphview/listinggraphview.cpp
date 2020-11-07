#include "listinggraphview.h"
#include "../../hooks/disassemblerhooks.h"
#include "../../models/contextmodel.h"
#include "../../redasmsettings.h"
#include "listingblockitem.h"
#include <rdapi/graph/functiongraph.h>
#include <rdapi/graph/layout.h>
#include <QResizeEvent>
#include <QScrollBar>
#include <QPainter>
#include <QAction>
#include <QMenu>

ListingGraphView::ListingGraphView(ICommand* command, QWidget *parent): GraphView(parent), m_command(command)
{
    this->setFocusPolicy(Qt::StrongFocus);
    this->setContextMenuPolicy(Qt::CustomContextMenu);
    this->setFont(REDasmSettings::font());

    connect(this, &ListingGraphView::customContextMenuRequested, this, [&](const QPoint&) {
        RDDocument* doc = RDContext_GetDocument(m_command->context().get());
        if(RDDocument_GetSize(doc)) m_contextmenu->popup(QCursor::pos());
    });
}

void ListingGraphView::goBack()
{
    m_command->goBack();

    RDDocumentItem item;
    if(m_command->getCurrentItem(&item)) this->updateGraph(item.address);
}

void ListingGraphView::goForward()
{
    m_command->goForward();

    RDDocumentItem item;
    if(m_command->getCurrentItem(&item)) this->updateGraph(item.address);
}

void ListingGraphView::copy() const
{
    ListingBlockItem* blockitem = static_cast<ListingBlockItem*>(this->selectedItem());
    //if(blockitem) return blockitem->renderer()->copy();
}

bool ListingGraphView::goToAddress(rd_address address)
{
    if(!m_command->goToAddress(address)) return false;
    return this->updateGraph(address);
}

bool ListingGraphView::goTo(const RDDocumentItem& item)
{
    if(!m_command->goTo(item)) return false;
    return this->updateGraph(item.address);
}

bool ListingGraphView::hasSelection() const { return m_command->hasSelection(); }
bool ListingGraphView::canGoBack() const { return m_command->canGoBack(); }
bool ListingGraphView::canGoForward() const { return m_command->canGoForward(); }
bool ListingGraphView::getCurrentItem(RDDocumentItem* item) const { return m_command->getCurrentItem(item); }

bool ListingGraphView::getCurrentSymbol(RDSymbol* symbol) const
{
    ListingBlockItem* blockitem = static_cast<ListingBlockItem*>(this->selectedItem());
    return blockitem->surface()->getCurrentSymbol(symbol);
}

const RDSurfacePos* ListingGraphView::position() const { return m_command->position(); }
const RDSurfacePos* ListingGraphView::selection() const { return m_command->selection(); }
SurfaceQt* ListingGraphView::surface() const { return nullptr; }
QString ListingGraphView::currentWord() const { return m_command->currentWord(); }
const RDContextPtr& ListingGraphView::context() const { return m_command->context(); }
QWidget* ListingGraphView::widget() { return this; }
void ListingGraphView::computed() { this->focusCurrentBlock(); }

void ListingGraphView::onFollowRequested(ListingBlockItem* block)
{
    RDSymbol symbol;
    //if(!block->renderer()->selectedSymbol(&symbol)) return;
    this->goToAddress(symbol.address);
}

void ListingGraphView::focusCurrentBlock()
{
    GraphViewItem* item = this->itemFromCurrentLine();
    if(!item) return;

    this->focusBlock(item);
    this->setSelectedBlock(item);
}

bool ListingGraphView::updateGraph(rd_address address)
{
    if(!RDFunctionGraph_Contains(m_graph, address)) return this->renderGraph();
    this->focusCurrentBlock();
    return true;
}

bool ListingGraphView::renderGraph()
{
    if(!m_contextmenu) m_contextmenu = DisassemblerHooks::instance()->createActions(this);
    RDDocument* doc = RDContext_GetDocument(m_command->context().get());

    RDDocumentItem item;
    if(!m_command->getCurrentItem(&item)) return false;

    auto loc = RDDocument_GetFunctionStart(doc, item.address);
    if(!loc.valid) return false;

    if(m_currentfunction && (loc.address == m_currentfunction->address)) // Don't render graph again
    {
        this->focusCurrentBlock();
        return true;
    }

    //FIXME: if(!RDDocument_GetInstructionItem(doc, loc.address, &item)) return false;

    RDGraph* graph = nullptr;

    if(!RDDocument_GetFunctionGraph(doc, loc.address, &graph))
    {
        m_currentfunction = std::nullopt;
        RD_Log(qUtf8Printable(QString("Graph rendering failed @ %1").arg(RD_ToHexAuto(loc.address))));
        return false;
    }

    m_currentfunction = item;
    this->setGraph(graph);
    this->focusCurrentBlock();
    return true;
}

void ListingGraphView::showEvent(QShowEvent *e)
{
    GraphView::showEvent(e);
    this->focusCurrentBlock();
}

void ListingGraphView::computeEdge(const RDGraphEdge& e)
{
    RDGraph_SetColor(m_graph, &e, qUtf8Printable(this->getEdgeColor(e).name()));
    RDGraph_SetLabel(m_graph, &e, qUtf8Printable(this->getEdgeLabel(e)));
}

void ListingGraphView::computeNode(GraphViewItem* item)
{
    auto* dbi = static_cast<ListingBlockItem*>(item);
    connect(dbi, &ListingBlockItem::followRequested, this, &ListingGraphView::onFollowRequested);
}

GraphViewItem* ListingGraphView::createItem(RDGraphNode n, const RDGraph* g)
{
    const RDFunctionBasicBlock* fbb = nullptr;

    if(!RDFunctionGraph_GetBasicBlock(m_graph, n, &fbb))
    {
        rd_log("Cannot find basic block");
        return nullptr;
    }

    return new ListingBlockItem(fbb, m_command, n, g, this);
}

QColor ListingGraphView::getEdgeColor(const RDGraphEdge& e) const
{
    const RDFunctionBasicBlock* fbb = nullptr;
    if(!RDFunctionGraph_GetBasicBlock(m_graph, e.source, &fbb)) return QColor();

    rd_type theme = RDFunctionBasicBlock_GetTheme(fbb, e.target);
    return (theme != Theme_Default) ? THEME_VALUE(theme) : QColor();
}

QString ListingGraphView::getEdgeLabel(const RDGraphEdge& e) const
{
    // const RDFunctionBasicBlock *fromfbb = nullptr, *tofbb = nullptr;;
    // if(!RDFunctionGraph_GetBasicBlock(m_graph, e.source, &fromfbb)) return QString();
    // if(!RDFunctionGraph_GetBasicBlock(m_graph, e.target, &tofbb)) return QString();

    // RDDocument* doc = RDContext_GetDocument(m_command->disassembler());
    // InstructionLock instruction(doc, RDFunctionBasicBlock_GetEndAddress(fromfbb));
    QString label;

    // if(instruction && (instruction->flags & InstructionFlags_Conditional))
    // {
    //     RDDocumentItem toitem;
    //     if(!RDFunctionBasicBlock_GetStartItem(tofbb, &toitem)) return QString();

    //     RDLocation loc = RDDisassembler_GetTarget(m_command->disassembler(), instruction->address);
    //     if(loc.valid) label = (loc.address == RDFunctionBasicBlock_GetStartAddress(tofbb)) ? "TRUE" : "FALSE";
    // }

    // if(!(RDFunctionBasicBlock_GetStartAddress(tofbb) > RDFunctionBasicBlock_GetStartAddress(fromfbb)))
        //label += !label.isEmpty() ? " (LOOP)" : "LOOP";

    return label;
}

GraphViewItem *ListingGraphView::itemFromCurrentLine() const
{
    RDDocumentItem item;
    if(!m_command->getCurrentItem(&item)) return nullptr;

    if(!IS_TYPE(&item, DocumentItemType_Function)) // Adjust to instruction
    {
        RDDocument* doc = RDContext_GetDocument(m_command->context().get());
        //FIXME: if(!RDDocument_GetInstructionItem(doc, item.address, &item)) return nullptr;
    }

    for(const auto& gvi : m_items)
    {
        ListingBlockItem* dbi = static_cast<ListingBlockItem*>(gvi);
        if(dbi->containsItem(item)) return gvi;
    }

    return nullptr;
}
