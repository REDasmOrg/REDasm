#ifndef FUNCTIONBLOCKITEM_H
#define FUNCTIONBLOCKITEM_H

#include "../../redasm/redasm.h"
#include "../../widgets/graphview/graphitems/graphtextitem.h"
#include "disassemblergraphdocument.h"

class FunctionBlockItem : public GraphTextItem
{
    Q_OBJECT

    public:
        FunctionBlockItem(REDasm::Disassembler* disassembler, REDasm::Graphing::Vertex *v, QObject* parent = NULL);
        ~FunctionBlockItem();

   public:
        void append(const REDasm::InstructionPtr &instruction);
        void append(const REDasm::SymbolPtr& symbol);

   protected:
        virtual int titleHeight() const;
        virtual QPoint origin() const;
        virtual QSize size() const;
        virtual void paint(QPainter *painter);

   private:
        REDasm::Disassembler* _disassembler;
        DisassemblerGraphDocument* _graphdocument;
};

#endif // FUNCTIONBLOCK_H
