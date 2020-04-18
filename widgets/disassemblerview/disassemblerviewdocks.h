#pragma once

#include <QAbstractItemView>
#include <QDockWidget>
#include <QTabWidget>
#include <QTableView>
#include <QTreeView>
#include <rdapi/rdapi.h>
#include "../../models/listingfiltermodel.h"
#include "../../models/calltreemodel.h"
#include "../../models/referencesmodel.h"
#include "../listingmap.h"

class DisassemblerViewDocks : public QObject
{
    Q_OBJECT

    public:
        explicit DisassemblerViewDocks(QObject *parent = nullptr);
        ~DisassemblerViewDocks();
        void setDisassembler(RDDisassembler* disassembler);

    public:
        ListingFilterModel* functionsModel() const;
        ReferencesModel* referencesModel() const;
        CallTreeModel* callTreeModel();
        QTableView* functionsView() const;
        QTreeView* referencesView() const;
        QTreeView* callgraphView() const;

    public slots:
        void initializeCallGraph(address_t address);
        void updateCallGraph();

    private:
        QDockWidget* findDock(const QString& objectname) const;
        void createCallTreeModel();
        void createFunctionsModel();
        void createReferencesModel();
        void createListingMap();

    private:
        QSet<event_t> m_events;
        RDDisassembler* m_disassembler{nullptr};
        QDockWidget *m_dockfunctions, *m_dockcalltree, *m_dockreferences, *m_docklistingmap;
        QTreeView *m_referencesview, *m_calltreeview;
        QTableView* m_functionsview;
        ListingFilterModel* m_functionsmodel;
        CallTreeModel* m_calltreemodel;
        ReferencesModel* m_referencesmodel;
        ListingMap* m_listingmap;
};
