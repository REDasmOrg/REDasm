#include "callgraphview.h"
#include "callgraphitem.h"

CallGraphView::CallGraphView(QWidget *parent) : GraphView(parent) { }
CallGraphView::~CallGraphView() { }

void CallGraphView::display(address_t address, REDasm::DisassemblerAPI *disassembler)
{
    m_callgraph = std::make_unique<REDasm::CallGraph>(disassembler->document());
    m_callgraph->walk(address);

    this->setGraph(m_callgraph.get());
    this->render(m_callgraph.get());
}

GraphItem *CallGraphView::createItem(REDasm::Graphing::Vertex *v) { return new CallGraphItem(v, this); }
