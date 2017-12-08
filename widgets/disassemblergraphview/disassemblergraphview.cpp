#include "disassemblergraphview.h"
#include <QGraphicsLinearLayout>

#define PADDING 20.0

DisassemblerGraphView::DisassemblerGraphView(QWidget *parent) : QGraphicsView(parent), _disassembler(NULL)
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
    this->_graph = listing.buildGraph(address);
    this->_scene->clear();

    if(!this->_graph)
        return;

    FunctionBlockItem* fbi = this->renderGraph(this->_graph, listing);

    if(fbi)
        this->_scene->addItem(fbi);
}

FunctionBlockItem* DisassemblerGraphView::renderGraph(const REDasm::Listing::GraphPathPtr &graph, REDasm::Listing& listing)
{
    if(graph->block.empty())
        return NULL;

    REDasm::SymbolTable* symboltable = listing.symbolTable();
    REDasm::SymbolPtr symbol = symboltable->symbol(graph->block.front());
    FunctionBlockItem* fbi = new FunctionBlockItem(this->_disassembler, "light");

    if(IS_LABEL(symbol))
        fbi->append(symbol);

    std::for_each(graph->block.begin(), graph->block.end(), [this, &listing, &fbi](address_t address) {
        REDasm::InstructionPtr instruction = listing[address];
        fbi->append(instruction);
    });

    std::for_each(graph->paths.begin(), graph->paths.end(), [this, &listing, &fbi](const REDasm::Listing::GraphPathPtr& graph) {
        FunctionBlockItem* childfbi = this->renderGraph(graph, listing);

        if(childfbi)
            childfbi->setParentItem(fbi);
    });

    this->repositionChildren(fbi);
    return fbi;
}

void DisassemblerGraphView::repositionChildren(FunctionBlockItem *currentfbi)
{
    QList<QGraphicsItem*> children = currentfbi->childItems();

    if(children.isEmpty())
        return;

    QRectF br = currentfbi->boundingRect();

    if(children.count() == 1)
    {
        children.first()->setPos(0, br.height() + PADDING);
        return;
    }

    int mid = children.count() / 2;
    QRectF childrenrect = currentfbi->childrenBoundingRect();

    QPointF itempos = QPoint(childrenrect.width() / 2, br.height() + PADDING);

    for(int i = mid; i >= 0; i--) // Left Part
    {
        QGraphicsItem* item = children[i];
        QRectF br = item->boundingRect();

        itempos.setX(itempos.x() - (br.width() + PADDING));
        item->setPos(itempos);
    }

    itempos = QPoint(childrenrect.width() / 2, br.height() + PADDING);

    for(int i = mid + 1; i < children.count(); i++) // Right Part
    {
        QGraphicsItem* item = children[i];
        QRectF br = item->boundingRect();

        itempos.setX(itempos.x() + (br.width() + PADDING));
        item->setPos(itempos);
    }
}
