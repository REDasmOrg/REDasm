#ifndef DISASSEMBLERVIEWDOCKS_H
#define DISASSEMBLERVIEWDOCKS_H

#include <QAbstractItemView>
#include <QDockWidget>
#include <QTabWidget>
#include <QTableView>
#include <QTreeView>
#include <redasm/disassembler/disassemblerapi.h>
#include "../../models/listingfiltermodel.h"
#include "../../models/callgraphmodel.h"
#include "../../models/referencesmodel.h"
#include "../listingmap.h"

class DisassemblerViewDocks : public QObject
{
    Q_OBJECT

    public:
        explicit DisassemblerViewDocks(QObject *parent = NULL);
        virtual ~DisassemblerViewDocks();
        void setDisassembler(const REDasm::DisassemblerPtr &disassembler);

    public:
        ListingFilterModel* functionsModel() const;
        ReferencesModel* referencesModel() const;
        CallGraphModel* callGraphModel();
        QTableView* functionsView() const;
        QTreeView* referencesView() const;
        QTreeView* callgraphView() const;

    public slots:
        void initializeCallGraph(address_t address);
        void updateCallGraph();

    private:
        QDockWidget* findDock(const QString& objectname) const;
        void createCallGraphModel();
        void createFunctionsModel();
        void createSymbolsModel();
        void createReferencesModel();
        void createListingMap();

    private:
        std::shared_ptr<REDasm::DisassemblerAPI> m_disassembler;
        QDockWidget *m_docksymbols, *m_dockreferences, *m_docklistingmap;
        QTreeView *m_referencesview, *m_callgraphview;
        QTableView* m_functionsview;
        QTabWidget* m_tabsmodel;
        ListingFilterModel* m_functionsmodel;
        CallGraphModel* m_callgraphmodel;
        ReferencesModel* m_referencesmodel;
        ListingMap* m_listingmap;
};

#endif // DISASSEMBLERVIEWDOCKS_H
