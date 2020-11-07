#pragma once

#include <rdapi/graph/functiongraph.h>
#include <rdapi/rdapi.h>
#include "../../hooks/icommand.h"
#include "../../renderer/surfacedocument.h"
#include "../graphview/graphviewitem.h"

class ListingBlockItem : public GraphViewItem
{
    Q_OBJECT

    public:
        explicit ListingBlockItem(const RDFunctionBasicBlock* fbb, ICommand* command, RDGraphNode node, const RDGraph* g, QWidget *parent = nullptr);
        const SurfaceQt* surface() const;
        bool containsItem(const RDDocumentItem& item) const;
        int currentRow() const override;
        void render(QPainter* painter, size_t state) override;
        QSize size() const override;

    protected:
        void itemSelectionChanged(bool selected) override;
        void mouseDoubleClickEvent(QMouseEvent *) override;
        void mousePressEvent(QMouseEvent *e) override;
        void mouseMoveEvent(QMouseEvent *e) override;

    signals:
        void followRequested(ListingBlockItem* block);

    private:
        SurfaceDocument* m_surface;
        const RDFunctionBasicBlock* m_basicblock;
        ICommand* m_command;
        RDContextPtr m_context;
};
