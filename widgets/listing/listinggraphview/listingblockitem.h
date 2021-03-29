#pragma once

#include <rdapi/graph/functiongraph.h>
#include <rdapi/rdapi.h>
#include "../../../renderer/surfacedocument.h"
#include "../../graphview/graphviewitem.h"

class ListingBlockItem : public GraphViewItem
{
    Q_OBJECT

    public:
        explicit ListingBlockItem(SurfaceQt* surface, const RDFunctionBasicBlock* fbb, RDGraphNode n, const RDGraph* g, QWidget *parent = nullptr);
        void render(QPainter* painter, size_t state) override;
        bool contains(rd_address address) const;
        int currentRow() const override;
        QSize size() const override;

    protected:
        void itemSelectionChanged(bool selected) override;
        void mouseDoubleClickEvent(QMouseEvent *) override;
        void mousePressEvent(QMouseEvent *e) override;
        void mouseMoveEvent(QMouseEvent *e) override;

    private:
        void localPosToSurface(const QPointF& pt, int* row, int* col) const;
        int startRow() const;

    Q_SIGNALS:
        void followRequested();

    private:
        const RDFunctionBasicBlock* m_basicblock;
        SurfaceQt* m_surface;
};
