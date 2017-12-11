#ifndef DISASSEMBLERGRAPHVIEW_H
#define DISASSEMBLERGRAPHVIEW_H

#include <QGraphicsView>
#include "../../redasm/disassembler/graph/graphbuilder.h"
#include "functionblockitem.h"

class DisassemblerGraphView : public QGraphicsView
{
    Q_OBJECT

    private:
        typedef std::map<REDasm::GraphBuilder::Node*, FunctionBlockItem*> NodeLookup;

    public:
        explicit DisassemblerGraphView(QWidget *parent = NULL);
        void setDisassembler(REDasm::Disassembler* disassembler);

    public slots:
        void display(address_t address);

    protected:
        virtual void wheelEvent(QWheelEvent *event);

    private:
        void renderGraph(REDasm::GraphBuilder &gb);
        void drawArrow(REDasm::GraphBuilder::Edge *edge, REDasm::GraphBuilder &gb);
        void drawArrow(const QPointF& from, const QPointF& to, const QColor &color);
        QPointF topCenter(REDasm::GraphBuilder& gb, REDasm::GraphBuilder::Node* node);
        QPointF bottomCenter(REDasm::GraphBuilder& gb, REDasm::GraphBuilder::Node* node);
        QPointF scenePoint(REDasm::GraphBuilder& gb, REDasm::GraphBuilder::Node* node, double x, double y) const;
        QPointF scenePoint(FunctionBlockItem *fbi, double x, double y) const;
        QPointF scenePoint(double x, double y) const;

    private:
        REDasm::Disassembler* _disassembler;
        QGraphicsScene* _scene;
};

#endif // DISASSEMBLERGRAPHVIEW_H
