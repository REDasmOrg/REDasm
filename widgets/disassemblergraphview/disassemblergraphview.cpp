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
    s64 y = this->itemPadding(), maxx = 0;

    for(auto& item : bylayer)
    {
        s64 x = this->itemPadding(), maxheight = 0;

        for(REDasm::Graphing::Vertex* v : item.second)
        {
            GraphItem* gi = NULL;

            if(!v->isFake())
            {
                gi = new FunctionBlockItem(this->_disassembler, "light", v, this);

                REDasm::FunctionGraphVertex* fgv = static_cast<REDasm::FunctionGraphVertex*>(v);
                auto it = listing.find(fgv->start);

                while(it != listing.end())
                {
                    REDasm::InstructionPtr instruction = *it;
                    static_cast<FunctionBlockItem*>(gi)->append(instruction);

                    if(instruction->address == fgv->end)
                        break;

                    it++;
                }
            }
            else
            {
                gi = new GraphItem(v, this);
                gi->resize(this->minimumSize(), 0);
            }

            gi->move(x, y);

            QSize sz = gi->size();
            x += sz.width() + this->itemPadding();

            if(sz.height() > maxheight)
                maxheight = sz.height();

            this->addItem(gi);
        }

        if(x > maxx)
            maxx = x;

        y += maxheight + this->minimumSize();
    }

    this->setGraphSize(QSize(maxx + this->minimumSize(), y + this->minimumSize()));
}
