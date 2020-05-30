#include "disassemblergraphview.h"
#include "../../hooks/disassemblerhooks.h"
#include "../../models/disassemblermodel.h"
#include "../../redasmsettings.h"
#include "disassemblerblockitem.h"
#include <rdapi/graph/functiongraph.h>
#include <rdapi/graph/layout.h>
#include <QResizeEvent>
#include <QScrollBar>
#include <QPainter>
#include <QAction>
#include <QMenu>

DisassemblerGraphView::DisassemblerGraphView(IDisassemblerCommand* command, QWidget *parent): GraphView(parent), m_command(command)
{
    this->setFocusPolicy(Qt::StrongFocus);
    this->setContextMenuPolicy(Qt::CustomContextMenu);
    this->setBlinkCursor(command->cursor());

    connect(this, &DisassemblerGraphView::customContextMenuRequested, this, [&](const QPoint&) {
        RDDocument* doc = RDDisassembler_GetDocument(m_command->disassembler());
        if(RDDocument_ItemsCount(doc)) m_contextmenu->popup(QCursor::pos());
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
    if(blockitem) return blockitem->renderer()->copy();
}

bool DisassemblerGraphView::gotoAddress(address_t address)
{
    if(!m_command->gotoAddress(address)) return false;
    return this->updateGraph(address);
}

bool DisassemblerGraphView::gotoItem(const RDDocumentItem& item)
{
    if(!m_command->gotoItem(item)) return false;
    return this->updateGraph(item.address);
}

bool DisassemblerGraphView::hasSelection() const { return m_command->hasSelection(); }
bool DisassemblerGraphView::canGoBack() const { return m_command->canGoBack(); }
bool DisassemblerGraphView::canGoForward() const { return m_command->canGoForward(); }
bool DisassemblerGraphView::getCurrentItem(RDDocumentItem* item) const { return m_command->getCurrentItem(item); }

bool DisassemblerGraphView::getSelectedSymbol(RDSymbol* symbol) const
{
    DisassemblerBlockItem* blockitem = static_cast<DisassemblerBlockItem*>(this->selectedItem());
    if(blockitem) return blockitem->renderer()->selectedSymbol(symbol);
    return false;
}

bool DisassemblerGraphView::ownsCursor(const RDCursor* cursor) const { return m_command->ownsCursor(cursor); }
const RDCursorPos* DisassemblerGraphView::currentPosition() const { return m_command->currentPosition(); }
const RDCursorPos* DisassemblerGraphView::currentSelection() const { return m_command->currentSelection(); }
QString DisassemblerGraphView::currentWord() const { return m_command->currentWord(); }
RDDisassembler* DisassemblerGraphView::disassembler() const { return m_command->disassembler(); }
RDCursor* DisassemblerGraphView::cursor() const { return m_command->cursor(); }
QWidget* DisassemblerGraphView::widget() { return this; }

void DisassemblerGraphView::computeLayout()
{
    const RDGraphNode* nodes = nullptr;
    size_t c = RDGraph_GetNodes(m_graph, &nodes);

    for(size_t i = 0; i < c; i++)
    {
        RDGraphNode n = nodes[i];
        const RDFunctionBasicBlock* fbb = nullptr;

        if(!RDFunctionGraph_GetBasicBlock(m_graph, n, &fbb))
        {
            rd_log("Cannot find basic block");
            return;
        }

        auto* dbi = new DisassemblerBlockItem(fbb, m_command, n, this->viewport());
        connect(dbi, &DisassemblerBlockItem::followRequested, this, &DisassemblerGraphView::onFollowRequested);

        m_items[n] = dbi;
        RDGraph_SetWidth(m_graph, n, dbi->width());
        RDGraph_SetHeight(m_graph, n, dbi->height());
    }

    const RDGraphEdge* edges = nullptr;
    c = RDGraph_GetEdges(m_graph, &edges);

    for(size_t i = 0; i < c; i++)
    {
        const RDGraphEdge& e = edges[i];
        RDGraph_SetColor(m_graph, &e, qUtf8Printable(this->getEdgeColor(e).name()));
        RDGraph_SetLabel(m_graph, &e, qUtf8Printable(this->getEdgeLabel(e)));
    }

    RDGraphLayout_Layered(m_graph, LayeredLayoutType_Medium);
    GraphView::computeLayout();
    this->focusCurrentBlock();
}

void DisassemblerGraphView::onFollowRequested(DisassemblerBlockItem* block)
{
    RDSymbol symbol;
    if(!block->renderer()->selectedSymbol(&symbol)) return;
    this->gotoAddress(symbol.address);
}

void DisassemblerGraphView::focusCurrentBlock()
{
    GraphViewItem* item = this->itemFromCurrentLine();
    if(!item) return;

    this->focusBlock(item);
    this->setSelectedBlock(item);
}

bool DisassemblerGraphView::updateGraph(address_t address)
{
    if(!RDFunctionGraph_Contains(m_graph, address)) return this->renderGraph();
    this->focusCurrentBlock();
    return true;
}

bool DisassemblerGraphView::renderGraph()
{
    if(!m_contextmenu)
        m_contextmenu = DisassemblerHooks::instance()->createActions(this);

    RDDocument* doc = RDDisassembler_GetDocument(m_command->disassembler());

    RDDocumentItem item;
    if(!m_command->getCurrentItem(&item)) return false;

    auto loc = RDDocument_FunctionStart(doc, item.address);
    if(!loc.valid) return false;

    if(m_currentfunction && (loc.address == m_currentfunction->address)) // Don't render graph again
    {
        this->focusCurrentBlock();
        return true;
    }

    if(!RDDocument_GetInstructionItem(doc, loc.address, &item)) return false;

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

void DisassemblerGraphView::onCursorBlink()
{
    GraphViewItem* item = this->selectedItem();
    if(item) item->invalidate();
}

QColor DisassemblerGraphView::getEdgeColor(const RDGraphEdge& e) const
{
    const RDFunctionBasicBlock* fbb = nullptr;
    if(!RDFunctionGraph_GetBasicBlock(m_graph, e.source, &fbb)) return QColor();

    const char* style = RDFunctionBasicBlock_GetStyle(fbb, e.target);
    return style ? THEME_VALUE(style) : QColor();
}

QString DisassemblerGraphView::getEdgeLabel(const RDGraphEdge& e) const
{
    const RDFunctionBasicBlock *fromfbb = nullptr, *tofbb = nullptr;;
    if(!RDFunctionGraph_GetBasicBlock(m_graph, e.source, &fromfbb)) return QString();
    if(!RDFunctionGraph_GetBasicBlock(m_graph, e.target, &tofbb)) return QString();

    RDDocument* doc = RDDisassembler_GetDocument(m_command->disassembler());
    InstructionLock instruction(doc, RDFunctionBasicBlock_GetEndAddress(fromfbb));
    QString label;

    if(instruction && (instruction->flags & InstructionFlags_Conditional))
    {
        RDDocumentItem toitem;
        if(!RDFunctionBasicBlock_GetStartItem(tofbb, &toitem)) return QString();

        RDLocation loc = RDDisassembler_GetTarget(m_command->disassembler(), instruction->address);
        if(loc.valid) label = (loc.address == RDFunctionBasicBlock_GetStartAddress(tofbb)) ? "TRUE" : "FALSE";
    }

    if(!(RDFunctionBasicBlock_GetStartAddress(tofbb) > RDFunctionBasicBlock_GetStartAddress(fromfbb)))
        label += !label.isEmpty() ? " (LOOP)" : "LOOP";

    return label;
}

GraphViewItem *DisassemblerGraphView::itemFromCurrentLine() const
{
    RDDocumentItem item;
    if(!m_command->getCurrentItem(&item)) return nullptr;

    if(!IS_TYPE(&item, DocumentItemType_Function)) // Adjust to instruction
    {
        RDDocument* doc = RDDisassembler_GetDocument(m_command->disassembler());
        if(!RDDocument_GetInstructionItem(doc, item.address, &item)) return nullptr;
    }

    for(const auto& gvi : m_items)
    {
        DisassemblerBlockItem* dbi = static_cast<DisassemblerBlockItem*>(gvi);
        if(dbi->containsItem(item)) return gvi;
    }

    return nullptr;
}
