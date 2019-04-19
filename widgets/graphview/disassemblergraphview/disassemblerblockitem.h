#ifndef DISASSEMBLERBLOCKITEM_H
#define DISASSEMBLERBLOCKITEM_H

#include <QTextDocument>
#include <redasm/graph/functiongraph.h>
#include "../../../renderer/listingdocumentrenderer.h"
#include "../graphviewitem.h"

class DisassemblerBlockItem : public GraphViewItem
{
    Q_OBJECT

    public:
        explicit DisassemblerBlockItem(const REDasm::Graphing::FunctionBasicBlock* fbb, const REDasm::DisassemblerPtr& disassembler, const REDasm::Graphing::Node& node, QWidget *parent = nullptr);
        virtual ~DisassemblerBlockItem();
        bool hasIndex(s64 index) const;

    public:
        virtual void render(QPainter* painter);
        virtual QSize size() const;

    protected:
        virtual void mousePressEvent(QMouseEvent *e);
        virtual void mouseMoveEvent(QMouseEvent *e);
        virtual void invalidate(bool notify = true);

    private:
        QSize documentSize() const;
        void setupDocument();

    private:
        const REDasm::Graphing::FunctionBasicBlock* m_basicblock;
        std::unique_ptr<ListingDocumentRenderer> m_renderer;
        REDasm::DisassemblerPtr m_disassembler;
        QTextDocument m_document;
        qreal m_charheight;
        QFont m_font;
};

#endif // DISASSEMBLERBLOCKITEM_H
