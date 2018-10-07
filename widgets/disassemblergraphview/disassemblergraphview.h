#ifndef DISASSEMBLERGRAPHVIEW_H
#define DISASSEMBLERGRAPHVIEW_H

#include <QtWebChannel>
#include "../graphview/graphview.h"
#include "../../redasm/disassembler/disassemblerapi.h"
#include "disassemblerwebchannel.h"

class DisassemblerGraphView : public GraphView
{
    Q_OBJECT

    public:
        explicit DisassemblerGraphView(QWidget *parent = NULL);
        void setDisassembler(REDasm::DisassemblerAPI* disassembler);
        void goTo(address_t address);
        void graph();

    protected:
        virtual QString getNodeTitle(const REDasm::Graphing::Node* n) const;
        virtual QString getNodeContent(const REDasm::Graphing::Node* n) const;
        virtual QColor getEdgeColor(const REDasm::Graphing::Node* from, const REDasm::Graphing::Node* to) const;

    protected slots:
        virtual void initializePage();
        void updateGraph();

    signals:
        void addressChanged(address_t address);
        void referencesRequested(address_t address);
        void switchView();

    private:
        REDasm::DisassemblerAPI* m_disassembler;
        REDasm::ListingItem* m_currentfunction;
        DisassemblerWebChannel* m_graphwebchannel;
        QWebChannel* m_webchannel;
};

#endif // DISASSEMBLERGRAPHVIEW_H
