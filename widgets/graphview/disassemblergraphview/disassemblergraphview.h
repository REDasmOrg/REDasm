#ifndef DISASSEMBLERGRAPHVIEW_H
#define DISASSEMBLERGRAPHVIEW_H

#include <QAbstractScrollArea>
#include <QList>
#include <redasm/graph/functiongraph.h>
#include "disassemblerblockitem.h"
#include "../graphview.h"

class DisassemblerGraphView : public GraphView
{
    Q_OBJECT

    public:
        explicit DisassemblerGraphView(QWidget *parent = nullptr);
        virtual ~DisassemblerGraphView();
        virtual void setDisassembler(const REDasm::DisassemblerPtr &disassembler);
        std::string currentWord();
        void goTo(address_t address);
        void focusCurrentBlock();
        bool renderGraph();

    protected:
        virtual QColor getEdgeColor(const REDasm::Graphing::Edge &e) const;
        virtual std::string getEdgeLabel(const REDasm::Graphing::Edge &e) const;
        virtual void mousePressEvent(QMouseEvent *e);
        virtual void mouseMoveEvent(QMouseEvent *e);
        virtual void mouseReleaseEvent(QMouseEvent* e);
        virtual void keyPressEvent(QKeyEvent *e);
        virtual void showEvent(QShowEvent* e);
        virtual void timerEvent(QTimerEvent* e);

    private:
        virtual void computeLayout();

    signals:
        void switchView();
        void hexDumpRequested(address_t address, u64 len);
        void referencesRequested(address_t address);
        void callGraphRequested(address_t address);
        void gotoDialogRequested();
        void switchToHexDump();

    private:
        const REDasm::ListingItem* m_currentfunction;
        int m_blinktimer;
};

#endif // DISASSEMBLERGRAPHVIEW_H
