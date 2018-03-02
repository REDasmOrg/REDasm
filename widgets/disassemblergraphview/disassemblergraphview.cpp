#include "disassemblergraphview.h"
#include "../../redasm/graph/graph_layout.h"
#include "../../redasm/disassembler/graph/functiongraph.h"

DisassemblerGraphView::DisassemblerGraphView(QWidget *parent) : GraphView(parent), _disassembler(NULL), _functiongraph(NULL)
{
}

DisassemblerGraphView::~DisassemblerGraphView()
{
    if(this->_functiongraph)
    {
        delete this->_functiongraph;
        this->_functiongraph = NULL;
    }
}

void DisassemblerGraphView::setDisassembler(REDasm::Disassembler *disassembler)
{
    this->_disassembler = disassembler;
}

void DisassemblerGraphView::display(address_t address)
{
    if(!this->_disassembler)
        return;

    if(this->_functiongraph)
        delete this->_functiongraph;

    this->_functiongraph = new REDasm::FunctionGraph(this->_disassembler->listing());
    this->_functiongraph->build(address);

    this->render(this->_functiongraph);
}

GraphItem *DisassemblerGraphView::createItem(REDasm::Graphing::Vertex *v)
{
    FunctionBlockItem* fbi = new FunctionBlockItem(this->_disassembler, "light", v, this);
    REDasm::FunctionGraphVertex* fgv = static_cast<REDasm::FunctionGraphVertex*>(v);
    REDasm::Listing& listing = this->_functiongraph->listing();
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
}
