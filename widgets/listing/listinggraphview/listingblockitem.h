#pragma once

#include <rdapi/graph/functiongraph.h>
#include <rdapi/rdapi.h>
#include "../../../renderer/surfacedocument.h"
#include "../../graphview/graphviewitem.h"

class ListingBlockItem : public GraphViewItem
{
    Q_OBJECT

    public:
        explicit ListingBlockItem(const RDContextPtr& ctx, const RDFunctionBasicBlock* fbb, RDGraphNode n, const RDGraph* g, QWidget *parent = nullptr);
        SurfaceQt* surface();
        bool containsItem(const RDDocumentItem& item) const;
        int currentRow() const override;
        void render(QPainter* painter, size_t state) override;
        QSize size() const override;

    protected:
        void itemSelectionChanged(bool selected) override;
        void mouseDoubleClickEvent(QMouseEvent *) override;
        void mousePressEvent(QMouseEvent *e) override;
        void mouseMoveEvent(QMouseEvent *e) override;

    Q_SIGNALS:
        void followRequested();

    private:
        const RDFunctionBasicBlock* m_basicblock;
        SurfaceDocument* m_surface;
};
