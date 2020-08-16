#pragma once

#include "../../../widgets/graphview/graphviewitem.h"

class RDILElementItem : public GraphViewItem
{
    Q_OBJECT

    public:
        explicit RDILElementItem(RDGraphNode node, const RDGraph* g, QObject *parent = nullptr);
        void render(QPainter* painter, size_t state) override;
        QSize size() const override;
};

