#pragma once

#include <QDockWidget>
#include <QSplitter>
#include "../../disassemblerlistingview/disassemblerlistingview.h"
#include "../../disassemblerlistingview/disassemblertextview.h"
#include "../../disassemblergraphview/disassemblergraphview.h"
#include "../hooks/icommandtab.h"

class ListingTab : public QWidget, public ICommandTab
{
    Q_OBJECT

    public:
        explicit ListingTab(const RDDisassemblerPtr& disassembler, QWidget *parent = nullptr);
        IDisassemblerCommand* command() const override;
        QWidget* widget() override;

    public slots:
        void switchToGraph();
        void switchToListing();
        void switchMode();

    protected:
        bool eventFilter(QObject *object, QEvent *event) override;

    private:
        DisassemblerListingView* m_listingview;
        DisassemblerGraphView* m_graphview;
};
