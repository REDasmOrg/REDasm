#ifndef FUNCTIONBLOCKITEM_H
#define FUNCTIONBLOCKITEM_H

#include "../../redasm/redasm.h"
#include "../../widgets/graphview/graphitems/graphtextitem.h"
#include "disassemblergraphdocument.h"

class FunctionBlockItem : public GraphTextItem
{
    Q_OBJECT

    public:
        FunctionBlockItem(REDasm::Disassembler* disassembler, const QString& theme, REDasm::Graphing::Vertex *v, QObject* parent = NULL);
        ~FunctionBlockItem();

   public:
        void append(const REDasm::InstructionPtr &instruction);
        void append(const REDasm::SymbolPtr& symbol);

   private:
        DisassemblerGraphDocument* _graphdocument;
};

#endif // FUNCTIONBLOCK_H
