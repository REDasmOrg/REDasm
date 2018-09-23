#ifndef FUNCTIONBLOCKITEM_H
#define FUNCTIONBLOCKITEM_H

#include "../../redasm/redasm.h"
#include "../../redasm/disassembler/disassemblerapi.h"
#include "../../widgets/graphview/graphitems/graphtextitem.h"

class FunctionBlockItem : public GraphTextItem
{
    Q_OBJECT

    public:
        FunctionBlockItem(REDasm::DisassemblerAPI* disassembler, REDasm::Graphing::Vertex *v, QObject* parent = NULL);

   public:
        void append(const REDasm::InstructionPtr &instruction);
        void append(const REDasm::SymbolPtr& symbol);

   protected:
        virtual int titleHeight() const;
        virtual QPoint origin() const;
        virtual QSize size() const;
        virtual void paint(QPainter *painter);

   private:
        REDasm::DisassemblerAPI* m_disassembler;
};

#endif // FUNCTIONBLOCK_H
