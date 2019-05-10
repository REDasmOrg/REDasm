#ifndef DISASSEMBLERBLOCKITEM_H
#define DISASSEMBLERBLOCKITEM_H

#include <QTextDocument>
#include <redasm/graph/functiongraph.h>
#include "../../../renderer/listingdocumentrenderer.h"
#include "../../../disassembleractions.h"
#include "../graphviewitem.h"

class DisassemblerBlockItem : public GraphViewItem
{
    Q_OBJECT

    public:
        explicit DisassemblerBlockItem(const REDasm::Graphing::FunctionBasicBlock* fbb, const REDasm::DisassemblerPtr& disassembler, const REDasm::Graphing::Node& node, QWidget *parent = nullptr);
        virtual ~DisassemblerBlockItem();
        std::string currentWord();
        DisassemblerActions* disassemblerActions() const;
        bool hasIndex(s64 index) const;

    public:
        void render(QPainter* painter, size_t state) override;
        QSize size() const override;

    protected:
        void itemSelectionChanged(bool selected) override;
        void mouseDoubleClickEvent(QMouseEvent *e) override;
        void mousePressEvent(QMouseEvent *e) override;
        void mouseMoveEvent(QMouseEvent *e) override;
        void invalidate(bool notify = true) override;

    private:
        QSize documentSize() const;
        void setupDocument();

    private:
        const REDasm::Graphing::FunctionBasicBlock* m_basicblock;
        std::unique_ptr<ListingDocumentRenderer> m_renderer;
        DisassemblerActions* m_actions;
        REDasm::DisassemblerPtr m_disassembler;
        QTextDocument m_document;
        qreal m_charheight;
        QFont m_font;
};

#endif // DISASSEMBLERBLOCKITEM_H
