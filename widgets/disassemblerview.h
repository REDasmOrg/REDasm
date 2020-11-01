#pragma once

#include <QWidget>
#include <QSet>
#include <future>
#include <rdapi/rdapi.h>
#include "../hooks/icommandtab.h"
#include "../hooks/itabletab.h"
#include "disassemblertabs/disassemblertabs.h"

class QDockWidget;
class ListingMapDock;
class TableTab;

class DisassemblerView : public QWidget
{
    Q_OBJECT

    public:
        explicit DisassemblerView(const RDContextPtr& ctx, QWidget *parent = nullptr);
        virtual ~DisassemblerView();
        QWidget* currentWidget() const;
        const RDContextPtr& disassembler() const;
        ITableTab* showSegments(Qt::DockWidgetArea area = Qt::NoDockWidgetArea);
        ITableTab* showFunctions(Qt::DockWidgetArea area = Qt::NoDockWidgetArea);
        ITableTab* showExports(Qt::DockWidgetArea area = Qt::NoDockWidgetArea);
        ITableTab* showImports(Qt::DockWidgetArea area = Qt::NoDockWidgetArea);
        ITableTab* showStrings(Qt::DockWidgetArea area = Qt::NoDockWidgetArea);
        ICommandTab* showListing();
        bool focusOn(QWidget* w);

    private:
        void tab(QWidget* w, int index = -1);
        void tabify(QDockWidget* first, QDockWidget* second);
        void dock(QWidget* w, Qt::DockWidgetArea area);
        void undock(QDockWidget* dw);
        template<typename T> ITableTab* findModelInTabs() const;
        ITableTab* findSymbolModelInTabs(rd_type type, rd_flag flags) const;
        TableTab* createTable(ListingItemModel* model, const QString& title);

    private:
        static void listenEvents(const RDEventArgs* e);

    private:
        RDContextPtr m_context;
        DisassemblerTabs* m_disassemblertabs;
        ListingMapDock* m_listingmapdock;
        QSet<QDockWidget*> m_docks;
        std::future<void> m_worker;
};

template<typename T>
ITableTab* DisassemblerView::findModelInTabs() const
{
    for(int i = 0; i < m_disassemblertabs->count(); i++)
    {
        auto* tabletab = dynamic_cast<ITableTab*>(m_disassemblertabs->widget(i));
        if(!tabletab) continue;

        if(dynamic_cast<T*>(tabletab->model())) return tabletab;
    }

    return nullptr;
}
