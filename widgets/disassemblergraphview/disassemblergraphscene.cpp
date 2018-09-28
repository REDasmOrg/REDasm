#include "disassemblergraphscene.h"
#include "functionblockitem.h"
#include "../graphview/graphmetrics.h"
#include <QColor>

DisassemblerGraphScene::DisassemblerGraphScene(QObject *parent): QGraphicsScene(parent), m_disassembler(NULL)
{
    this->setBackgroundBrush(QColor("azure"));
}

void DisassemblerGraphScene::setDisassembler(REDasm::DisassemblerAPI *disassembler) { m_disassembler = disassembler; }

void DisassemblerGraphScene::graph()
{
    this->clear();

    REDasm::ListingDocument* doc = m_disassembler->document();
    REDasm::Graphing::FunctionGraph fg(doc);
    fg.build(doc->currentItem()->address);

    REDasm::Graphing::LayeredGraph lgraph(&fg);
    this->addBlocks(lgraph);
}

void DisassemblerGraphScene::addBlocks(const REDasm::Graphing::LayeredGraph& lgraph)
{
    int y = GraphMetrics::itemPadding();

    for(const REDasm::Graphing::VertexList& vl : lgraph)
    {
        int x = GraphMetrics::itemPadding(), maxheight = 0;
        QGraphicsItem* item = NULL;

        for(REDasm::Graphing::Vertex* v : vl)
        {
            if(v->isFake())
                continue;

            //FIXME: item = new FunctionBlockItem(m_disassembler, v);
            //FIXME: item->setPos(x, y);
            //FIXME: this->addItem(item);

            //FIXME: QRectF r = item->boundingRect();
            //FIXME: x += r.width() + GraphMetrics::itemPadding();
            //FIXME: maxheight = std::max(maxheight, static_cast<int>(r.height()));
        }

        y += maxheight + GraphMetrics::itemPadding();
    }
}

void DisassemblerGraphScene::addLines(const REDasm::Graphing::LayeredGraph &lgraph)
{

}
