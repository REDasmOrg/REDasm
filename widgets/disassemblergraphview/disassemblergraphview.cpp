#include "disassemblergraphview.h"

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
    REDasm::GraphBuilder gb(listing);
    gb.build(address);

    this->beginInsertion();
        this->_addedblocks.clear();
        this->removeAll();
        this->addBlock(gb.rootNode(), NULL, gb, listing);
    this->endInsertion();
}

void DisassemblerGraphView::addBlock(const REDasm::GraphNodePtr &node, FunctionBlockItem* parentitem, REDasm::GraphBuilder& gb, REDasm::Listing& listing)
{
    if(this->_addedblocks.find(node->address) != this->_addedblocks.end())
        return;

    this->_addedblocks.insert(node->address);
    FunctionBlockItem* fbi = new FunctionBlockItem(this->_disassembler, "light", this);

    std::for_each(node->items.begin(), node->items.end(), [this, &listing, fbi](address_t address) {
        fbi->append(listing[address]);
    });

    if(parentitem)
        this->addEdge(parentitem, fbi);
    else
        this->addRoot(fbi);

    REDasm::GraphBuilder::NodeList edges = gb.getEdges(node);

    std::for_each(edges.begin(), edges.end(), [this, fbi, &gb, &listing](address_t edge) {
        this->addBlock(gb.getNode(edge), fbi, gb, listing);
    });
}
