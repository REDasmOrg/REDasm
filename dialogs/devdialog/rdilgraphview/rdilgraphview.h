#pragma once

#include "../../../widgets/graphview/graphview.h"

class RDILGraphView: public GraphView
{
    Q_OBJECT

    public:
        RDILGraphView(QWidget* parent = 0);

    protected:
        GraphViewItem* createItem(RDGraphNode n, const RDGraph* g) override;
};
