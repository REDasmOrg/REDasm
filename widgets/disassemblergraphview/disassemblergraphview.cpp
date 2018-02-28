#include "disassemblergraphview.h"
#include "../../redasm/graph/graph_layout.h"
#include "../../redasm/disassembler/graph/functiongraph.h"

DisassemblerGraphView::DisassemblerGraphView(QWidget *parent) : GraphView(parent)
{
}

void DisassemblerGraphView::setDisassembler(REDasm::Disassembler *disassembler)
{
    this->_disassembler = disassembler;
}

void DisassemblerGraphView::display(address_t address)
{
    if(!this->_disassembler)
        return;

    REDasm::Listing& listing = this->_disassembler->listing();
    REDasm::FunctionGraph gb(listing);
    gb.build(address);

    this->removeAll();
    this->addBlocks(gb, listing);
}

void DisassemblerGraphView::addBlocks(const REDasm::FunctionGraph &gb, REDasm::Listing &listing)
{
    REDasm::Graphing::VertexByLayer bylayer = gb.sortByLayer();
    s64 y = 0;

    for(auto& item : bylayer)
    {
        s64 x = 0;

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

            if(sz.height() > y)
                y = sz.height();

            this->addItem(fbi);
        }

        y += this->itemPadding();
    }
}
