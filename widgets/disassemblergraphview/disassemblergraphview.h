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
        void setDisassembler(REDasm::Disassembler* disassembler);

    public slots:
        void display(address_t address);

    private:
        void addBlocks(const REDasm::FunctionGraph &gb, REDasm::Listing &listing);

    private:
        REDasm::Disassembler* _disassembler;
};

#endif // DISASSEMBLERGRAPHVIEW_H
