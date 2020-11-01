#pragma once

#include <rdapi/graph/functiongraph.h>
#include <rdapi/rdapi.h>
#include "../../hooks/icommand.h"
#include "../../renderer/surfacerenderer.h"
#include "../graphview/graphviewitem.h"

class DisassemblerBlockItem : public GraphViewItem
{
    Q_OBJECT

    public:
        explicit DisassemblerBlockItem(const RDFunctionBasicBlock* fbb, ICommand* command, RDGraphNode node, const RDGraph* g, QWidget *parent = nullptr);
        const SurfaceRenderer* renderer() const;
        bool containsItem(const RDDocumentItem& item) const;
        int currentLine() const override;
        void render(QPainter* painter, size_t state) override;
        QSize size() const override;

    protected:
        void mouseDoubleClickEvent(QMouseEvent *) override;
        void mousePressEvent(QMouseEvent *e) override;
        void mouseMoveEvent(QMouseEvent *e) override;

    private:
        QSize documentSize() const;

    signals:
        void followRequested(DisassemblerBlockItem* block);

    private:
        SurfaceRenderer* m_surface;
        const RDFunctionBasicBlock* m_basicblock;
        ICommand* m_command;
        RDContextPtr m_context;
};
