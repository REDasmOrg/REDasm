#pragma once

#include "../graphview/graphviewitem.h"
#include "../hooks/isurface.h"
#include <QPalette>

class CallGraphItem : public GraphViewItem
{
    Q_OBJECT

    public:
        explicit CallGraphItem(const RDContextPtr& ctx, RDGraphNode node, const RDGraph* g, QObject *parent = nullptr);
        void render(QPainter* painter, size_t state) override;
        QSize size() const override;

    protected:
        void mouseDoubleClickEvent(QMouseEvent *) override;

    signals:
        void fetchMore(rd_address address);

    private:
        rd_address m_address{RD_NVAL};
        QPalette m_palette;
        RDContextPtr m_context;
        QString m_label;
        QSize m_size;
};

