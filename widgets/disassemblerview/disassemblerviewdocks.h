#ifndef DISASSEMBLERVIEWDOCKS_H
#define DISASSEMBLERVIEWDOCKS_H

#include <QAbstractItemView>
#include <QDockWidget>
#include <QTabWidget>
#include <QTableView>
#include <QTreeView>
#include <redasm/disassembler/disassembler.h>
#include "../../models/listingfiltermodel.h"
#include "../../models/calltreemodel.h"
#include "../../models/referencesmodel.h"
#include "../listingmap.h"

class DisassemblerViewDocks : public QObject
{
    Q_OBJECT

    public:
        explicit DisassemblerViewDocks(QObject *parent = nullptr);
        void setDisassembler(const REDasm::DisassemblerPtr &disassembler);

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
        std::shared_ptr<REDasm::Disassembler> m_disassembler;
        QDockWidget *m_dockfunctions, *m_dockcalltree, *m_dockreferences, *m_docklistingmap;
        QTreeView *m_referencesview, *m_calltreeview;
        QTableView* m_functionsview;
        ListingFilterModel* m_functionsmodel;
        CallTreeModel* m_calltreemodel;
        ReferencesModel* m_referencesmodel;
        ListingMap* m_listingmap;
};

#endif // DISASSEMBLERVIEWDOCKS_H
