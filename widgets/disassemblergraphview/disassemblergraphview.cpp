#include "disassemblergraphview.h"
#include "../../hooks/disassemblerhooks.h"
#include "../../models/contextmodel.h"
#include "../../redasmsettings.h"
#include "disassemblerblockitem.h"
#include <rdapi/graph/functiongraph.h>
#include <rdapi/graph/layout.h>
#include <QResizeEvent>
#include <QScrollBar>
#include <QPainter>
#include <QAction>
#include <QMenu>

DisassemblerGraphView::DisassemblerGraphView(ICommand* command, QWidget *parent): GraphView(parent), m_command(command)
{
    this->setFocusPolicy(Qt::StrongFocus);
    this->setContextMenuPolicy(Qt::CustomContextMenu);
    this->setFont(REDasmSettings::font());

    connect(this, &DisassemblerGraphView::customContextMenuRequested, this, [&](const QPoint&) {
        RDDocument* doc = RDContext_GetDocument(m_command->context().get());
        if(RDDocument_GetSize(doc)) m_contextmenu->popup(QCursor::pos());
    });
}

void DisassemblerGraphView::goBack()
{
    m_command->goBack();

    RDDocumentItem item;
    if(m_command->getCurrentItem(&item)) this->updateGraph(item.address);
}

void DisassemblerGraphView::goForward()
{
    m_command->goForward();

    RDDocumentItem item;
    if(m_command->getCurrentItem(&item)) this->updateGraph(item.address);
}

void DisassemblerGraphView::copy() const
{
    DisassemblerBlockItem* blockitem = static_cast<DisassemblerBlockItem*>(this->selectedItem());
    //if(blockitem) return blockitem->renderer()->copy();
}

bool DisassemblerGraphView::goToAddress(rd_address address)
{
    if(!m_command->goToAddress(address)) return false;
    return this->updateGraph(address);
}

bool DisassemblerGraphView::goTo(const RDDocumentItem& item)
{
    if(!m_command->goTo(item)) return false;
    return this->updateGraph(item.address);
}

bool DisassemblerGraphView::hasSelection() const { return m_command->hasSelection(); }
bool DisassemblerGraphView::canGoBack() const { return m_command->canGoBack(); }
bool DisassemblerGraphView::canGoForward() const { return m_command->canGoForward(); }
bool DisassemblerGraphView::getCurrentItem(RDDocumentItem* item) const { return m_command->getCurrentItem(item); }

bool DisassemblerGraphView::getSelectedSymbol(RDSymbol* symbol) const
{
    DisassemblerBlockItem* blockitem = static_cast<DisassemblerBlockItem*>(this->selectedItem());
    //if(blockitem) return blockitem->renderer()->selectedSymbol(symbol);
    return false;
}

const RDSurfacePos* DisassemblerGraphView::currentPosition() const { return m_command->currentPosition(); }
const RDSurfacePos* DisassemblerGraphView::currentSelection() const { return m_command->currentSelection(); }
const RDDocumentItem* DisassemblerGraphView::firstItem() const { return m_command->firstItem(); }
const RDDocumentItem* DisassemblerGraphView::lastItem() const { return m_command->lastItem(); }
SurfaceRenderer* DisassemblerGraphView::surface() const { return nullptr; }
QString DisassemblerGraphView::currentWord() const { return m_command->currentWord(); }
const RDContextPtr& DisassemblerGraphView::context() const { return m_command->context(); }
QWidget* DisassemblerGraphView::widget() { return this; }
void DisassemblerGraphView::computed() { this->focusCurrentBlock(); }

void DisassemblerGraphView::onFollowRequested(DisassemblerBlockItem* block)
{
    RDSymbol symbol;
    //if(!block->renderer()->selectedSymbol(&symbol)) return;
    this->goToAddress(symbol.address);
}

void DisassemblerGraphView::focusCurrentBlock()
{
    GraphViewItem* item = this->itemFromCurrentLine();
    if(!item) return;

    this->focusBlock(item);
    this->setSelectedBlock(item);
}

bool DisassemblerGraphView::updateGraph(rd_address address)
{
    if(!RDFunctionGraph_Contains(m_graph, address)) return this->renderGraph();
    this->focusCurrentBlock();
    return true;
}

bool DisassemblerGraphView::renderGraph()
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

void DisassemblerGraphView::showEvent(QShowEvent *e)
{
    GraphView::showEvent(e);
    this->focusCurrentBlock();
}

void DisassemblerGraphView::computeEdge(const RDGraphEdge& e)
{
    RDGraph_SetColor(m_graph, &e, qUtf8Printable(this->getEdgeColor(e).name()));
    RDGraph_SetLabel(m_graph, &e, qUtf8Printable(this->getEdgeLabel(e)));
}

void DisassemblerGraphView::computeNode(GraphViewItem* item)
{
    auto* dbi = static_cast<DisassemblerBlockItem*>(item);
    connect(dbi, &DisassemblerBlockItem::followRequested, this, &DisassemblerGraphView::onFollowRequested);
}

GraphViewItem* DisassemblerGraphView::createItem(RDGraphNode n, const RDGraph* g)
{
    const RDFunctionBasicBlock* fbb = nullptr;

    if(!RDFunctionGraph_GetBasicBlock(m_graph, n, &fbb))
    {
        rd_log("Cannot find basic block");
        return nullptr;
    }

    return new DisassemblerBlockItem(fbb, m_command, n, g, this);
}

void DisassemblerGraphView::onCursorBlink()
{
    GraphViewItem* item = this->selectedItem();
    if(item) item->invalidate();
}

QColor DisassemblerGraphView::getEdgeColor(const RDGraphEdge& e) const
{
    const RDFunctionBasicBlock* fbb = nullptr;
    if(!RDFunctionGraph_GetBasicBlock(m_graph, e.source, &fbb)) return QColor();

    rd_type theme = RDFunctionBasicBlock_GetTheme(fbb, e.target);
    return (theme != Theme_Default) ? THEME_VALUE(theme) : QColor();
}

QString DisassemblerGraphView::getEdgeLabel(const RDGraphEdge& e) const
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

GraphViewItem *DisassemblerGraphView::itemFromCurrentLine() const
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
        DisassemblerBlockItem* dbi = static_cast<DisassemblerBlockItem*>(gvi);
        if(dbi->containsItem(item)) return gvi;
    }

    return nullptr;
}
