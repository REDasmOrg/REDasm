#ifndef DISASSEMBLERVIEW_H
#define DISASSEMBLERVIEW_H

#include <QGraphicsView>
#include <QWidget>
#include <QLabel>
#include <QMenu>
#include <qhexedit.h>
#include "../../models/callgraphmodel.h"
#include "../../models/listingfiltermodel.h"
#include "../../models/symboltablemodel.h"
#include "../../models/referencesmodel.h"
#include "../../models/segmentsmodel.h"
#include "../../dialogs/gotodialog.h"
#include "../../redasm/disassembler/disassembler.h"
#include "../disassemblergraphview/disassemblergraphview.h"
#include "../disassemblerlistingview/disassemblerlistingview.h"

namespace Ui {
class DisassemblerView;
}

class DisassemblerView : public QWidget
{
    Q_OBJECT

    public:
        explicit DisassemblerView(QLabel* lblstatus, QPushButton* pbstatus, QWidget *parent = 0);
        ~DisassemblerView();
        REDasm::DisassemblerAPI* disassembler();
        void setDisassembler(REDasm::DisassemblerAPI* disassembler);

    private slots:
        void changeDisassemblerStatus();
        void checkDisassemblerStatus();
        void modelIndexSelected(const QModelIndex& index);
        void updateCurrentFilter(int index);
        void gotoXRef(const QModelIndex &index);
        void goTo(const QModelIndex &index);
        void showModelReferences();
        void showReferences(address_t address);
        void displayAddress(address_t address);
        void initializeCallGraph(address_t address);
        void updateCallGraph();
        void displayCurrentReferences();
        void log(const QString& s);
        void switchGraphListing();
        void showFilter();
        void clearFilter();
        void showHexDump(address_t address);
        void showMenu(const QPoint&);
        void showGoto();

    protected:
        bool eventFilter(QObject* obj, QEvent* e);

    private:
        void createActions();
        void filterSymbols();
        ListingFilterModel* getSelectedFilterModel();

    private:
        Ui::DisassemblerView *ui;
        DisassemblerGraphView* m_disassemblergraphview;
        DisassemblerListingView* m_disassemblerlistingview;
        QModelIndex m_currentindex;
        QHexDocument* m_hexdocument;
        QMenu* m_contextmenu;
        QLabel* m_lblstatus;
        QPushButton* m_pbstatus;
        REDasm::DisassemblerAPI* m_disassembler;
        ListingFilterModel *m_segmentsmodel, *m_functionsmodel, *m_importsmodel, *m_exportsmodel, *m_stringsmodel;
        CallGraphModel* m_callgraphmodel;
        ReferencesModel* m_referencesmodel;
        QAction* m_actsetfilter;
        QActionGroup* m_viewactions;
};

#endif // DISASSEMBLERVIEW_H
