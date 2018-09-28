#ifndef DISASSEMBLERGRAPHSCENE_H
#define DISASSEMBLERGRAPHSCENE_H

#include <QGraphicsScene>
#include "../../redasm/disassembler/disassemblerapi.h"
#include "../../redasm/disassembler/graph/functiongraph.h"

class DisassemblerGraphScene : public QGraphicsScene
{
    Q_OBJECT

    public:
        explicit DisassemblerGraphScene(QObject *parent = NULL);
        void setDisassembler(REDasm::DisassemblerAPI* disassembler);
        void graph();

    private:
        void addBlocks(const REDasm::Graphing::LayeredGraph& lgraph);
        void addLines(const REDasm::Graphing::LayeredGraph& lgraph);

    private:
        REDasm::DisassemblerAPI* m_disassembler;
};

#endif // DISASSEMBLERGRAPHSCENE_H
