#ifndef DISASSEMBLERGRAPHVIEW_H
#define DISASSEMBLERGRAPHVIEW_H

#include "../graphview/graphview.h"
#include "../../redasm/disassembler/graph/functiongraph.h"
#include "functionblockitem.h"

class DisassemblerGraphView : public GraphView
{
    Q_OBJECT

    public:
        explicit DisassemblerGraphView(QWidget *parent = NULL);
        ~DisassemblerGraphView();
        void setDisassembler(REDasm::Disassembler* disassembler);

    public slots:
        void display(address_t address);

    protected:
        virtual GraphItem* createItem(REDasm::Graphing::Vertex* v);

    private:
        REDasm::Disassembler* _disassembler;
        REDasm::FunctionGraph* _functiongraph;
};

#endif // DISASSEMBLERGRAPHVIEW_H
