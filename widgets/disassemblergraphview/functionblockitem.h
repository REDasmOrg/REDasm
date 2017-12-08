#ifndef FUNCTIONBLOCKITEM_H
#define FUNCTIONBLOCKITEM_H

#include <QGraphicsTextItem>
#include "../../redasm/redasm.h"
#include "disassemblergraphdocument.h"

class FunctionBlockItem : public QGraphicsTextItem
{
    public:
        FunctionBlockItem(REDasm::Disassembler* disassembler, const QString& theme);
        ~FunctionBlockItem();

   public:
        void append(const REDasm::InstructionPtr &instruction);
        void append(const REDasm::SymbolPtr& symbol);
        virtual void paint(QPainter *painter, const QStyleOptionGraphicsItem *option, QWidget *widget);

   private:
        DisassemblerGraphDocument* _graphdocument;
};

#endif // FUNCTIONBLOCK_H
