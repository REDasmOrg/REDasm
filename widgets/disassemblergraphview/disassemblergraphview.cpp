#include "disassemblergraphview.h"

#define SCENE_MARGIN -20

DisassemblerGraphView::DisassemblerGraphView(QWidget *parent) : QGraphicsView(parent)
{
    this->_scene = new QGraphicsScene(this);
    this->setScene(this->_scene);
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
    this->renderGraph(gb);
}

void DisassemblerGraphView::renderGraph(REDasm::GraphBuilder &gb)
{
    std::map<REDasm::GraphBuilder::Node*, FunctionBlockItem*> items;
    REDasm::Listing& listing = this->_disassembler->listing();

    gb.iterateBlocks([this, &items, &listing](REDasm::GraphBuilder::Node* node, const REDasm::GraphBuilder::Block& block, double& width, double& height) {
        FunctionBlockItem* fbi = new FunctionBlockItem(this->_disassembler, "light");

        for(auto it = block.begin(); it != block.end(); it++)
            fbi->append(listing[*it]);

        QRectF r = fbi->boundingRect();
        width = r.width();
        height = r.height();

        items[node] = fbi;
    });

    gb.layout();
    this->_scene->clear();

    QRectF r = this->sceneRect();
    r.adjust(SCENE_MARGIN, SCENE_MARGIN, SCENE_MARGIN, SCENE_MARGIN);
    this->setSceneRect(QRect(0, 0, 5000, 5000));

    std::for_each(items.begin(), items.end(), [this, gb](const std::pair<REDasm::GraphBuilder::Node*, FunctionBlockItem*>& item) {
        double x = 0, y = 0;
        gb.position(item.first, x, y);
        item.second->setPos(this->mapToScene(x, y));
        this->_scene->addItem(item.second);
    });

}
