#ifndef DISASSEMBLERGRAPHVIEW_H
#define DISASSEMBLERGRAPHVIEW_H

#include "../graphview/graphview.h"
#include "../../redasm/disassembler/disassemblerapi.h"
#include "../../redasm/disassembler/graph/functiongraph.h"
#include "functionblockitem.h"

class DisassemblerGraphView : public GraphView
{
    Q_OBJECT

    public:
        explicit DisassemblerGraphView(QWidget *parent = NULL);
        void setDisassembler(REDasm::DisassemblerAPI* disassembler);
        void graph();

    protected:
        virtual GraphItem* createItem(REDasm::Graphing::NodeData* v);

    private:
        REDasm::DisassemblerAPI* m_disassembler;
};

#endif // DISASSEMBLERGRAPHVIEW_H
