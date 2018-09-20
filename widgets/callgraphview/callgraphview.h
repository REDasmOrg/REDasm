#ifndef CALLGRAPHVIEW_H
#define CALLGRAPHVIEW_H

#include "../graphview/graphview.h"
#include "../../redasm/disassembler/disassembler.h"
#include "../../redasm/disassembler/graph/callgraph.h"

class CallGraphView : public GraphView
{
    Q_OBJECT

    public:
        explicit CallGraphView(QWidget *parent = NULL);
        ~CallGraphView();
        void display(address_t address, REDasm::DisassemblerAPI* disassembler);

    protected:
        virtual GraphItem* createItem(REDasm::Graphing::Vertex* v);

    private:
        std::unique_ptr<REDasm::CallGraph> m_callgraph;
};

#endif // CALLGRAPHVIEW_H
