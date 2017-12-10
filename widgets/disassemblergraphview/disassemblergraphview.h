#ifndef DISASSEMBLERGRAPHVIEW_H
#define DISASSEMBLERGRAPHVIEW_H

#include <QGraphicsView>
#include "../../redasm/disassembler/graph/graphbuilder.h"
#include "functionblockitem.h"

class DisassemblerGraphView : public QGraphicsView
{
    Q_OBJECT

    public:
        explicit DisassemblerGraphView(QWidget *parent = NULL);
        void setDisassembler(REDasm::Disassembler* disassembler);

    public slots:
        void display(address_t address);

    private:
        void renderGraph(REDasm::GraphBuilder &gb);

    private:
        REDasm::Disassembler* _disassembler;
        QGraphicsScene* _scene;
};

#endif // DISASSEMBLERGRAPHVIEW_H
