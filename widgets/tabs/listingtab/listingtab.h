#pragma once

#include <QDockWidget>
#include <QSplitter>
#include "../../listingview/listingview.h"
#include "../../listinggraphview/listinggraphview.h"
#include "../hooks/icommandtab.h"

class ListingTab : public QWidget, public ICommandTab
{
    Q_OBJECT

    public:
        explicit ListingTab(const RDContextPtr& disassembler, QWidget *parent = nullptr);
        ICommand* command() const override;
        QWidget* widget() override;

    public slots:
        void switchToGraph();
        void switchToListing();
        void switchMode();

    protected:
        bool eventFilter(QObject *object, QEvent *event) override;

    private:
        ListingView* m_listingview;
        ListingGraphView* m_graphview;
};
