#ifndef DISASSEMBLERGRAPHVIEW_H
#define DISASSEMBLERGRAPHVIEW_H

#include <QtWebChannel>
#include <redasm/disassembler/disassemblerapi.h>
#include "disassemblerwebchannel.h"
#include "../graphview/graphview.h"

class DisassemblerGraphView : public GraphView
{
    Q_OBJECT

    public:
        explicit DisassemblerGraphView(QWidget *parent = NULL);
        void setDisassembler(REDasm::DisassemblerAPI* disassembler);
        void goTo(address_t address);
        bool graph();

    protected:
        virtual void configureActions();
        virtual QString getNodeContent(const REDasm::Graphing::Node* n) const;
        virtual QColor getEdgeColor(const REDasm::Graphing::Node* from, const REDasm::Graphing::Node* to) const;
        virtual QString getEdgeLabel(const REDasm::Graphing::Node* from, const REDasm::Graphing::Node* to) const;
        virtual bool eventFilter(QObject* obj, QEvent* e);
        virtual void mousePressEvent(QMouseEvent* e);
        virtual void keyPressEvent(QKeyEvent* e);

    protected slots:
        virtual void initializePage();
        void updateGraph();

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
        REDasm::DisassemblerAPI* m_disassembler;
        REDasm::ListingItem* m_currentfunction;
        DisassemblerWebChannel* m_graphwebchannel;
        QWebChannel* m_webchannel;
};

#endif // DISASSEMBLERGRAPHVIEW_H
