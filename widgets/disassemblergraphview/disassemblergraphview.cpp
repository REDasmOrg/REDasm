#include "disassemblergraphview.h"
#include "../../models/disassemblermodel.h"
#include "../../redasmsettings.h"
#include <rdapi/graph/functiongraph.h>
#include <rdapi/graph/layout.h>
#include <QResizeEvent>
#include <QScrollBar>
#include <QPainter>
#include <QAction>

DisassemblerGraphView::DisassemblerGraphView(IDisassemblerCommand* command, QWidget *parent): GraphView(command, parent)
{
    this->setFocusPolicy(Qt::StrongFocus);

    //r_evt::subscribe(REDasm::StandardEvents::Cursor_PositionChanged, this, [&](const REDasm::EventArgs*) {
        //if(!this->isVisible()) return;
        //this->renderGraph();
        //if(!this->hasFocus()) this->focusCurrentBlock();
    //});
}

DisassemblerGraphView::~DisassemblerGraphView()
{
    //r_evt::ungroup(this);
}

bool DisassemblerGraphView::isCursorInGraph() const { return this->itemFromCurrentLine() != nullptr; }

void DisassemblerGraphView::computeLayout()
{
    const RDGraphNode* nodes = nullptr;
    size_t c = RDGraph_GetNodes(m_graph, &nodes);

    for(size_t i = 0; i < c; i++)
    {
        RDGraphNode n = nodes[i];
        const RDFunctionBasicBlock* fbb = nullptr;
        assert(RDFunctionGraph_GetBasicBlock(m_graph, n, &fbb));

        auto* dbi = new DisassemblerBlockItem(fbb, m_command, n, this->viewport());
        connect(dbi, &DisassemblerBlockItem::followRequested, this, &DisassemblerGraphView::onFollowRequested);
        connect(dbi, &DisassemblerBlockItem::menuRequested, this, &DisassemblerGraphView::onMenuRequested);

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

void DisassemblerGraphView::onFollowRequested(const QPointF& localpos)
{
    //if(!m_disassembleractions->renderer()) return;

    //if(!m_disassembleractions->followUnderCursor()) static_cast<ListingRendererCommon*>(m_disassembleractions->renderer())->selectWordAt(localpos);
    //else this->focusCurrentBlock();
}

void DisassemblerGraphView::onMenuRequested()
{
    //if(!m_disassembleractions->renderer()) return;
    //m_disassembleractions->popup(QCursor::pos());
}

void DisassemblerGraphView::goTo(address_t address)
{
    m_command->gotoAddress(address);
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
    RDDocument* doc = RDDisassembler_GetDocument(m_command->disassembler());

    RDDocumentItem item;
    if(!m_command->getCurrentItem(&item)) return false;

    auto loc = RDDocument_FunctionStart(doc, item.address);
    if(!loc.valid) return false;

    if(m_currentfunction && (loc.address == m_currentfunction->address)) // Don't render graph again
        return true;

    if(!RDDocument_GetInstructionItem(doc, loc.address, &item)) return false;

    RDGraph* graph = nullptr;

    if(!RDDocument_GetFunctionGraph(doc, loc.address, &graph))
    {
        m_currentfunction = std::nullopt;
        RD_Log(qUtf8Printable(QString("Graph rendering failed @ %1").arg(RD_ToHex(loc.address))));
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

void DisassemblerGraphView::selectedItemChangedEvent()
{
    GraphViewItem* selecteditem = this->selectedItem();

    // if(selecteditem)
    //     m_disassembleractions->setCurrentRenderer(static_cast<DisassemblerBlockItem*>(selecteditem)->renderer());
    // else
    //     m_disassembleractions->setCurrentRenderer(nullptr);

    GraphView::selectedItemChangedEvent();
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

    if(item.type != DocumentItemType_Function) // Adjust to instruction
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

void DisassemblerGraphView::mousePressEvent(QMouseEvent *e)
{
    //r_doc->cursor().disable();
    GraphView::mousePressEvent(e);
}

void DisassemblerGraphView::mouseMoveEvent(QMouseEvent *e)
{
    GraphView::mouseMoveEvent(e);
    //GraphViewItem* item = this->selectedItem();
    //if(item) r_doc->cursor().enable();
}
