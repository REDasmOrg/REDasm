#ifndef DISASSEMBLERBLOCKITEM_H
#define DISASSEMBLERBLOCKITEM_H

#include <QTextDocument>
#include <redasm/graph/functiongraph.h>
#include "../graphviewitem.h"

class DisassemblerBlockItem : public GraphViewItem
{
    Q_OBJECT

    public:
        explicit DisassemblerBlockItem(const REDasm::Graphing::FunctionBasicBlock* fbb, REDasm::DisassemblerAPI* disassembler, QWidget *parent = nullptr);
        bool hasIndex(s64 index) const;

    public:
        virtual void render(QPainter* painter);
        virtual QSize size() const;

    private:
        QSize documentSize() const;
        void setupDocument();

    private:
        const REDasm::Graphing::FunctionBasicBlock* m_basicblock;
        REDasm::DisassemblerAPI* m_disassembler;
        QTextDocument m_document;
        int m_charheight;
};

#endif // DISASSEMBLERBLOCKITEM_H
