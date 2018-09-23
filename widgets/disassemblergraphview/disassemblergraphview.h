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
        void setDisassembler(REDasm::DisassemblerAPI* disassembler);

    public slots:
        void display(address_t address);

    protected:
        virtual GraphItem* createItem(REDasm::Graphing::Vertex* v);

    private:
        REDasm::DisassemblerAPI* m_disassembler;
        std::unique_ptr<REDasm::FunctionGraph> m_functiongraph;
};

#endif // DISASSEMBLERGRAPHVIEW_H
