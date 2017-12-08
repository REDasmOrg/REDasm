#ifndef DISASSEMBLERGRAPHVIEW_H
#define DISASSEMBLERGRAPHVIEW_H

#include <QGraphicsView>
#include "functionblockitem.h"

class DisassemblerGraphView : public QGraphicsView
{
    Q_OBJECT

    public:
        explicit DisassemblerGraphView(QWidget *parent = nullptr);
        void setDisassembler(REDasm::Disassembler* disassembler);

    public slots:
        void display(address_t address);

    private:
        FunctionBlockItem *renderGraph(const REDasm::Listing::GraphPathPtr& graph, REDasm::Listing &listing);
        void repositionChildren(FunctionBlockItem* currentfbi);

    private:
        REDasm::Listing::GraphPathPtr _graph;
        REDasm::Disassembler* _disassembler;
        std::set<address_t> _splitpoints;
        std::stack<FunctionBlockItem*> _stack;
        QGraphicsScene* _scene;
};

#endif // DISASSEMBLERGRAPHVIEW_H
