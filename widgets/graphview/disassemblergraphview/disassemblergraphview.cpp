#include "disassemblergraphview.h"
#include "../../../models/disassemblermodel.h"
#include "../../../redasmsettings.h"
#include <redasm/graph/layout/layeredlayout.h>
#include <QResizeEvent>
#include <QScrollBar>
#include <QPainter>
#include <QDebug>
#include <QAction>

DisassemblerGraphView::DisassemblerGraphView(QWidget *parent): GraphView(parent), m_currentfunction(nullptr) { }
DisassemblerGraphView::~DisassemblerGraphView() { }

void DisassemblerGraphView::computeLayout()
{
    for(const auto& n : this->graph()->nodes())
    {
        const auto* fbb = static_cast<REDasm::Graphing::FunctionGraph*>(this->graph())->data(n);
        auto* dbi = new DisassemblerBlockItem(fbb, m_disassembler, n, this->viewport());

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
        this->goBack();
    else if(e->button() == Qt::ForwardButton)
        this->goForward();

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
