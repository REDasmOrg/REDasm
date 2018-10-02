#ifndef FUNCTIONBLOCKITEM_H
#define FUNCTIONBLOCKITEM_H

#include "../../widgets/graphview/graphitems/graphtextitem.h"
#include "../../renderer/listinggraphrenderer.h"
#include "../../redasm/disassembler/disassemblerapi.h"

class FunctionBlockItem : public GraphTextItem
{
    Q_OBJECT

    public:
        FunctionBlockItem(REDasm::DisassemblerAPI* disassembler, REDasm::Graphing::NodeData *data, QObject* parent = NULL);

   private:
        REDasm::DisassemblerAPI* m_disassembler;
        std::unique_ptr<ListingGraphRenderer> m_renderer;
};

#endif // FUNCTIONBLOCK_H
