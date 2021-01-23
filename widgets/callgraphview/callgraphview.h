#pragma once

#include <rdapi/rdapi.h>
#include "../hooks/isurface.h"
#include "../graphview/graphview.h"

class CallGraphView : public GraphView
{
    Q_OBJECT

    public:
        explicit CallGraphView(const RDContextPtr& ctx, QWidget *parent = nullptr);
        void walk(rd_address address);

    protected:
        GraphViewItem* createItem(RDGraphNode n, const RDGraph* g) override;

    private slots:
        void onFetchMode(rd_address address);

    private:
        rd_ptr<RDGraph> m_callgraph;
        RDContextPtr m_context;
};

