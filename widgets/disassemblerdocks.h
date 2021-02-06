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
        KDDockWidgets::DockWidget* showListing() const;
        void showSegments() const;
        void showFunctions() const;
        void showExports() const;
        void showImports() const;
        void showStrings() const;

    private:
        TableTab* createTable(ListingItemModel* model, const QString& title) const;
        static void listenEvents(const RDEventArgs* e);

    private:
        RDContextPtr m_context;
        ListingMap* m_listingmap{nullptr};
        std::future<void> m_worker;
};
