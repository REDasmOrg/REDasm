#include "disassemblergraphview.h"
#include "../../redasm/graph/graph_layout.h"
#include "../../redasm/disassembler/graph/functiongraph.h"

DisassemblerGraphView::DisassemblerGraphView(QWidget *parent) : GraphView(parent), m_disassembler(NULL)
{
}

void DisassemblerGraphView::setDisassembler(REDasm::DisassemblerAPI *disassembler) { m_disassembler = disassembler; }

void DisassemblerGraphView::display(address_t address)
{
    if(!m_disassembler)
        return;

    m_functiongraph = std::make_unique<REDasm::FunctionGraph>(m_disassembler->document());
    m_functiongraph->build(address);

    /*
    this->setGraph(this->_functiongraph);
    this->render(this->_functiongraph);
    */
}

GraphItem *DisassemblerGraphView::createItem(REDasm::Graphing::Vertex *v)
{
    /*
    FunctionBlockItem* fbi = new FunctionBlockItem(this->_disassembler, v, this);
    REDasm::FunctionGraphVertex* fgv = static_cast<REDasm::FunctionGraphVertex*>(v);
    REDasm::InstructionsPool& listing = this->_functiongraph->listing();
    auto it = listing.find(fgv->start);

    while(it != listing.end())
    {
        REDasm::InstructionPtr instruction = *it;
        fbi->append(instruction);

        if(instruction->address == fgv->end)
            break;

        it++;
    }

    return fbi;
    */

    return NULL;
}
