#include "callgraphview.h"
#include "callgraphitem.h"

CallGraphView::CallGraphView(QWidget *parent) : GraphView(parent)
{

}

CallGraphView::~CallGraphView()
{

}

void CallGraphView::display(address_t address, REDasm::Disassembler* disassembler)
{
    this->_callgraph = std::make_unique<REDasm::CallGraph>(disassembler->instructions());
    this->_callgraph->walk(address);

    this->setGraph(this->_callgraph.get());
    this->render(this->_callgraph.get());
}

GraphItem *CallGraphView::createItem(REDasm::Graphing::Vertex *v)
{
    return new CallGraphItem(v, this);
}
