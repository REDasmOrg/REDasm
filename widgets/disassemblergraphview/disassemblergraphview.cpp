#include "disassemblergraphview.h"
#include "../../redasm/disassembler/graph/functiongraph.h"
#include "../../renderer/listinggraphrenderer.h"
#include <QTextDocument>

DisassemblerGraphView::DisassemblerGraphView(QWidget *parent): GraphView(parent), m_disassembler(NULL) { }
void DisassemblerGraphView::setDisassembler(REDasm::DisassemblerAPI *disassembler) { m_disassembler = disassembler; }

void DisassemblerGraphView::graph()
{
    REDasm::ListingDocument* doc = m_disassembler->document();
    REDasm::Graphing::FunctionGraph graph(doc);
    graph.build(doc->currentItem()->address);
    this->setGraph(graph);
}

QString DisassemblerGraphView::getNodeContent(const REDasm::Graphing::Node *n)
{
    const REDasm::Graphing::FunctionBlock* fb = static_cast<const REDasm::Graphing::FunctionBlock*>(n);
    ListingGraphRenderer lgr(m_disassembler);

    QTextDocument textdocument;
    lgr.render(fb->startidx, fb->count(), &textdocument);
    return textdocument.toPlainText();
}
