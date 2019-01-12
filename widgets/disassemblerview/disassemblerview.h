#ifndef DISASSEMBLERVIEW_H
#define DISASSEMBLERVIEW_H

#include <QProgressBar>
#include <QLineEdit>
#include <QMenu>
#include <redasm/disassembler/disassembler.h>
#include <QHexView/qhexview.h>
#include "../../models/callgraphmodel.h"
#include "../../models/listingfiltermodel.h"
#include "../../models/symboltablemodel.h"
#include "../../models/referencesmodel.h"
#include "../../models/segmentsmodel.h"
#include "../../dialogs/gotodialog.h"
#include "../disassemblergraphview/disassemblergraphview.h"
#include "../disassemblerlistingview/disassemblerlistingview.h"
#include "themeprovider.h"

namespace Ui {
class DisassemblerView;
}

class DisassemblerView : public QWidget
{
    Q_OBJECT

    public:
        explicit DisassemblerView(QPushButton* pbstatus, QLineEdit* lefilter, QWidget *parent = NULL);
        ~DisassemblerView();
        REDasm::Disassembler* disassembler();
        void setDisassembler(REDasm::Disassembler* disassembler);
        void toggleFilter();
        void showFilter();
        void clearFilter();

    private slots:
        void changeDisassemblerStatus();
        void checkDisassemblerStatus();
        void modelIndexSelected(const QModelIndex& index);
        void checkHexEdit(int index);
        void updateCurrentFilter(int index);
        void gotoXRef(const QModelIndex &index);
        void goTo(const QModelIndex &index);
        void showModelReferences();
        void showReferences(address_t address);
        void displayAddress(address_t address);
        void initializeCallGraph(address_t address);
        void updateCallGraph();
        void displayCurrentReferences();
        void switchGraphListing();
        void switchToHexDump();
        void selectToHexDump(address_t address, u64 len);
        void showMenu(const QPoint&);
        void showGoto();

    private:
        void syncHexEdit();
        void createActions();
        void filterSymbols();
        void showListingOrGraph();
        ListingFilterModel* getSelectedFilterModel();

    private:
        Ui::DisassemblerView *ui;
        DisassemblerGraphView* m_disassemblergraphview;
        DisassemblerListingView* m_disassemblerlistingview;
        QModelIndex m_currentindex;
        QHexDocument* m_hexdocument;
        QMenu* m_contextmenu;
        QPushButton* m_pbstatus;
        QLineEdit* m_lefilter;
        std::unique_ptr<REDasm::Disassembler> m_disassembler;
        ListingFilterModel *m_segmentsmodel, *m_functionsmodel, *m_importsmodel, *m_exportsmodel, *m_stringsmodel;
        CallGraphModel* m_callgraphmodel;
        ReferencesModel* m_referencesmodel;
        QAction* m_actsetfilter;
        QActionGroup* m_viewactions;
};

#endif // DISASSEMBLERVIEW_H
