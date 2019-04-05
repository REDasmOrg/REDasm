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
        void goTo(address_t address);
        void focusCurrentBlock();
        bool renderGraph();

    protected:
        virtual QColor getEdgeColor(const REDasm::Graphing::Edge &e) const;
        virtual std::string getEdgeLabel(const REDasm::Graphing::Edge &e) const;
        virtual void mouseReleaseEvent(QMouseEvent* e);
        virtual void keyPressEvent(QKeyEvent *e);
        virtual void showEvent(QShowEvent* e);

    private:
        virtual void computeLayout();

    private slots:
        void adjustActions();
        void showCallGraph();
        void printFunctionHexDump();
        void goBack();
        void goForward();

    signals:
        void callGraphRequested(address_t address);
        void referencesRequested(address_t address);
        void switchView();

    private:
        QAction *m_actrename, *m_actxrefs, *m_actfollow, *m_actcallgraph, *m_acthexdump, *m_actback, *m_actforward;
        const REDasm::ListingItem* m_currentfunction;
};

#endif // DISASSEMBLERGRAPHVIEW_H
