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
        void graph();

    protected:
        virtual QString getNodeContent(const REDasm::Graphing::Node* n);
        virtual QColor getEdgeColor(const REDasm::Graphing::Node* from, const REDasm::Graphing::Node* to);

    protected slots:
        virtual void initializePage();

    signals:
        void addressChanged(address_t address);
        void switchView();

    private:
        REDasm::DisassemblerAPI* m_disassembler;
        QWebChannel* m_webchannel;
        DisassemblerWebChannel* m_graphwebchannel;
};

#endif // DISASSEMBLERGRAPHVIEW_H
