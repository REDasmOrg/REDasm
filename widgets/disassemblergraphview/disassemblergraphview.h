#ifndef DISASSEMBLERGRAPHVIEW_H
#define DISASSEMBLERGRAPHVIEW_H

#include "../graphview/graphview.h"
#include "../../redasm/disassembler/graph/graphbuilder.h"
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
        void addBlock(const REDasm::GraphNodePtr& node, FunctionBlockItem *parentitem, REDasm::GraphBuilder &gb, REDasm::Listing &listing);

    private:
        REDasm::Disassembler* _disassembler;
        std::set<address_t> _addedblocks;
};

#endif // DISASSEMBLERGRAPHVIEW_H
