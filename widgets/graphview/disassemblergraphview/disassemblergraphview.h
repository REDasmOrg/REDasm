#pragma once

#include <QAbstractScrollArea>
#include <QList>
#include <redasm/disassembler/model/functiongraph.h>
#include "disassemblerblockitem.h"
#include "../graphview.h"

class DisassemblerGraphView : public GraphView
{
    Q_OBJECT

    public:
        explicit DisassemblerGraphView(QWidget *parent = nullptr);
        virtual ~DisassemblerGraphView();
        void setDisassembler(const REDasm::DisassemblerPtr &disassembler) override;
        bool isCursorInGraph() const;
        REDasm::String currentWord();

    public slots:
        void goTo(address_t address);
        void focusCurrentBlock();
        bool renderGraph();

    private:
        QColor getEdgeColor(const REDasm::Edge &e) const;
        REDasm::String getEdgeLabel(const REDasm::Edge &e) const;
        GraphViewItem* itemFromCurrentLine() const;

    protected:
        void mousePressEvent(QMouseEvent *e) override;
        void mouseMoveEvent(QMouseEvent *e) override;
        void mouseReleaseEvent(QMouseEvent* e) override;
        void keyPressEvent(QKeyEvent *e) override;
        void showEvent(QShowEvent* e) override;
        void timerEvent(QTimerEvent* e) override;
        void selectedItemChangedEvent() override;
        void computeLayout() override;

    private slots:
        void onFollowRequested(const QPointF &localpos);
        void onMenuRequested();

    signals:
        void switchView();
        void hexDumpRequested(address_t address, u64 len);
        void referencesRequested(address_t address);
        void callGraphRequested(address_t address);
        void itemInformationRequested();
        void gotoDialogRequested();
        void switchToHexDump();

    private:
        REDasm::ListingItem m_currentfunction;
        DisassemblerActions* m_disassembleractions;
        int m_blinktimer;
};
