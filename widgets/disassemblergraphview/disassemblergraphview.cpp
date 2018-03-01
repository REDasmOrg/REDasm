#include "disassemblergraphview.h"
#include "../../redasm/graph/graph_layout.h"
#include "../../redasm/disassembler/graph/functiongraph.h"

DisassemblerGraphView::DisassemblerGraphView(QWidget *parent) : GraphView(parent), _functiongraph(NULL)
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

    REDasm::Listing& listing = this->_disassembler->listing();
    this->_functiongraph = new REDasm::FunctionGraph(listing);
    this->_functiongraph->build(address);

    this->removeAll();
    this->addBlocks(listing);
}

void DisassemblerGraphView::addBlocks(REDasm::Listing &listing)
{
    REDasm::Graphing::VertexByLayer bylayer = this->_functiongraph->sortByLayer();
    s64 y = this->itemPadding();

    for(auto& item : bylayer)
    {
        s64 x = this->itemPadding(), maxheight = 0;

        for(REDasm::Graphing::Vertex* v : item.second)
        {
            REDasm::FunctionGraphVertex* fgv = static_cast<REDasm::FunctionGraphVertex*>(v);
            FunctionBlockItem* fbi = new FunctionBlockItem(this->_disassembler, "light", v, this);
            fbi->move(x, y);

            auto it = listing.find(fgv->start);

            while(it != listing.end())
            {
                REDasm::InstructionPtr instruction = *it;
                fbi->append(instruction);

                if(instruction->address == fgv->end)
                    break;

                it++;
            }

            QSize sz = fbi->size();
            x += sz.width() + this->itemPadding();

            if(sz.height() > maxheight)
                maxheight = sz.height();

            this->addItem(fbi);
        }

        y += maxheight + this->itemPadding();
    }
}
