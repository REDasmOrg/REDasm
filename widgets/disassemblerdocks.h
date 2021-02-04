#pragma once

#include <QObject>
#include <QSet>
#include <future>
#include <rdapi/rdapi.h>
#include <kddockwidgets/DockWidget.h>
#include "tabs/tabletab/tabletab.h"
#include "disassemblertabs/disassemblertabs.h"

class ListingMap;
class TableTab;

class DisassemblerDocks : public QObject
{
    Q_OBJECT

    public:
        explicit DisassemblerDocks(QObject *parent = nullptr);
        virtual ~DisassemblerDocks();
        const RDContextPtr& context() const;
        void setContext(const RDContextPtr& ctx);
        KDDockWidgets::DockWidget* showListing();
        void showSegments();
        void showFunctions();
        void showExports();
        void showImports();
        void showStrings();

    private:
        TableTab* createTable(ListingItemModel* model, const QString& title);
        static void listenEvents(const RDEventArgs* e);

    private:
        RDContextPtr m_context;
        KDDockWidgets::DockWidget* m_listingdock{nullptr};
        ListingMap* m_listingmap{nullptr};
        std::future<void> m_worker;
};
