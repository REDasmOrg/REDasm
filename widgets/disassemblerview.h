#pragma once

#include <QWidget>
#include <QSet>
#include <future>
#include <rdapi/rdapi.h>
#include "tabs/tabletab/tabletab.h"
#include "disassemblertabs/disassemblertabs.h"

class QDockWidget;
class ListingMapDock;
class TableTab;

class DisassemblerView : public QWidget
{
    Q_OBJECT

    public:
        explicit DisassemblerView(QWidget *parent = nullptr);
        virtual ~DisassemblerView();
        QWidget* currentWidget() const;
        const RDContextPtr& context() const;
        void showSegments(Qt::DockWidgetArea area = Qt::NoDockWidgetArea);
        void showFunctions(Qt::DockWidgetArea area = Qt::NoDockWidgetArea);
        void showExports(Qt::DockWidgetArea area = Qt::NoDockWidgetArea);
        void showImports(Qt::DockWidgetArea area = Qt::NoDockWidgetArea);
        void showStrings(Qt::DockWidgetArea area = Qt::NoDockWidgetArea);
        QWidget* showListing();
        bool focusOn(QWidget* w);
        void setContext(const RDContextPtr& ctx);

    private:
        void tab(QWidget* w, int index = -1);
        void tabify(QDockWidget* first, QDockWidget* second);
        void dock(QWidget* w, Qt::DockWidgetArea area);
        void undock(QDockWidget* dw);
        template<typename T> TableTab* findModelInTabs() const;
        TableTab* findSymbolModelInTabs(rd_type type, rd_flag flags) const;
        TableTab* createTable(ListingItemModel* model, const QString& title);

    private:
        static void listenEvents(const RDEventArgs* e);

    private:
        RDContextPtr m_context;
        DisassemblerTabs* m_disassemblertabs{nullptr};
        ListingMapDock* m_listingmapdock{nullptr};
        QSet<QDockWidget*> m_docks;
        std::future<void> m_worker;
};

template<typename T>
TableTab* DisassemblerView::findModelInTabs() const {
    for(int i = 0; i < m_disassemblertabs->count(); i++) {
        auto* tabletab = dynamic_cast<TableTab*>(m_disassemblertabs->widget(i));
        if(!tabletab) continue;

        if(dynamic_cast<T*>(tabletab->model())) return tabletab;
    }

    return nullptr;
}
