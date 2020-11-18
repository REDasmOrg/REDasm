#include "listinggraphview.h"
#include "../../../hooks/disassemblerhooks.h"
#include "../../../models/contextmodel.h"
#include "../../../redasmsettings.h"
#include "listingblockitem.h"
#include <rdapi/graph/functiongraph.h>
#include <rdapi/graph/layout.h>
#include <QApplication>
#include <QResizeEvent>
#include <QScrollBar>
#include <QPainter>
#include <QAction>
#include <QMenu>

ListingGraphView::ListingGraphView(const RDContextPtr& ctx, QWidget *parent): GraphView(parent), m_context(ctx)
{
    this->setFocusPolicy(Qt::StrongFocus);
    this->setContextMenuPolicy(Qt::CustomContextMenu);
    this->setFont(REDasmSettings::font());
}

void ListingGraphView::linkTo(ISurface* s) { /* m_surface->linkTo(s->surface()); */ }
void ListingGraphView::unlink() { /* m_surface->unlink(); */ }

void ListingGraphView::goBack()
{
    m_rootsurface->goBack();

    RDDocumentItem item;
    if(m_rootsurface->getCurrentItem(&item)) this->renderGraph(&item);
}

void ListingGraphView::goForward()
{
    m_rootsurface->goForward();

    RDDocumentItem item;
    if(m_rootsurface->getCurrentItem(&item)) this->renderGraph(&item);
}

void ListingGraphView::copy() const { m_rootsurface->copy(); }

bool ListingGraphView::goToAddress(rd_address address)
{
    if(!m_rootsurface->goToAddress(address)) return false;

    RDDocumentItem item;
    if(!m_rootsurface->getCurrentItem(&item)) return false;

    this->renderGraph(&item);
    return true;
}

bool ListingGraphView::goTo(const RDDocumentItem* item)
{
    if(!m_rootsurface->goTo(item)) return false;
    return this->renderGraph(item);
}

bool ListingGraphView::hasSelection() const { return m_rootsurface->hasSelection(); }
bool ListingGraphView::canGoBack() const { return m_rootsurface->canGoBack(); }
bool ListingGraphView::canGoForward() const { return m_rootsurface->canGoForward(); }

bool ListingGraphView::getCurrentItem(RDDocumentItem* item) const
{
    auto* isurface = this->selectedSurface();
    return isurface ? isurface->getCurrentItem(item) : false;
}

bool ListingGraphView::getCurrentSymbol(RDSymbol* symbol) const
{
    auto* isurface = this->selectedSurface();
    return isurface ? isurface->getCurrentSymbol(symbol) : false;
}

SurfaceQt* ListingGraphView::surface() const { return m_rootsurface; }
QString ListingGraphView::currentWord() const { return m_rootsurface->getCurrentWord(); }
const RDContextPtr& ListingGraphView::context() const { return m_context; }
QWidget* ListingGraphView::widget() { return this; }
void ListingGraphView::computed() { this->focusCurrentBlock(); }

void ListingGraphView::onFollowRequested()
{
    RDSymbol symbol;
    if(!m_rootsurface->getCurrentSymbol(&symbol)) return;
    this->goToAddress(symbol.address);
}

void ListingGraphView::focusCurrentBlock()
{
    GraphViewItem* item = this->itemFromCurrentLine();
    if(!item) return;

    this->focusBlock(item);
    this->setSelectedBlock(item);
}

bool ListingGraphView::renderGraph(const RDDocumentItem* item)
{
    if(!item) return false;

    if(m_graph && RDFunctionGraph_Contains(m_graph, item->address))
    {
        this->focusCurrentBlock();
        return true;
    }

    auto loc = RDContext_GetFunctionStart(m_context.get(), item->address);
    if(!loc.valid) return false;

    if(m_currentfunction && (loc.address == m_currentfunction->address)) // Don't render graph again
    {
        this->focusCurrentBlock();
        return true;
    }

    RDGraph* graph = nullptr;
    RDDocument* doc = RDContext_GetDocument(m_context.get());

    if(!RDDocument_GetFunctionGraph(doc, loc.address, &graph))
    {
        m_currentfunction = std::nullopt;
        RD_Log(qUtf8Printable(QString("Graph rendering failed @ %1").arg(RD_ToHexAuto(loc.address))));
        return false;
    }

    m_currentfunction = *item;
    m_rootsurface = nullptr;
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


    auto* b = new ListingBlockItem(m_context, fbb, n, g, this);

    if(n != RDGraph_GetRoot(g))
    {
        if(m_rootsurface)
            b->surface()->linkTo(m_rootsurface); // Link all to root surface
    }
    else
        m_rootsurface = b->surface();

    return b;
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
    auto* surface = this->selectedSurface();
    if(!surface) return nullptr;

    RDDocumentItem item;
    if(!surface->getCurrentItem(&item)) return nullptr;

    for(const auto& gvi : m_items)
    {
        ListingBlockItem* dbi = static_cast<ListingBlockItem*>(gvi);
        if(dbi->containsItem(item)) return gvi;
    }

    return nullptr;
}

SurfaceQt* ListingGraphView::selectedSurface() const
{
    auto* item = static_cast<ListingBlockItem*>(this->selectedItem());
    return item ? item->surface() : nullptr;
}
