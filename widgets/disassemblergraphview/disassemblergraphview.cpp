#include "disassemblergraphview.h"

DisassemblerGraphView::DisassemblerGraphView(QWidget *parent): GraphView(parent), m_disassembler(NULL) { }
void DisassemblerGraphView::setDisassembler(REDasm::DisassemblerAPI *disassembler) { m_disassembler = disassembler; }

void DisassemblerGraphView::graph()
{
    REDasm::ListingDocument* doc = m_disassembler->document();
    REDasm::Graphing::FunctionGraph* graph = new REDasm::Graphing::FunctionGraph(doc);
    graph->build(doc->currentItem()->address);
    this->setGraph(graph);
}

GraphItem *DisassemblerGraphView::createItem(REDasm::Graphing::NodeData *v) { return new FunctionBlockItem(m_disassembler, v, this); }
