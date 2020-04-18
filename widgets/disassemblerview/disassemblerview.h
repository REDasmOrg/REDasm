#pragma once

#include <QProgressBar>
#include <QLineEdit>
#include <QMenu>
#include <QHexView/qhexview.h>
#include <rdapi/rdapi.h>
#include "../../models/symboltablemodel.h"
#include "../../models/segmentsmodel.h"
#include "../../dialogs/gotodialog/gotodialog.h"
#include "../graphview/disassemblergraphview/disassemblergraphview.h"
#include "../disassemblerlistingview/disassemblerlistingview.h"
#include "disassemblerviewactions.h"
#include "disassemblerviewdocks.h"
#include "../themeprovider.h"

namespace Ui {
class DisassemblerView;
}

class DisassemblerView : public QWidget
{
    Q_OBJECT

    public:
        explicit DisassemblerView(QLineEdit* lefilter, QWidget *parent = nullptr);
        virtual ~DisassemblerView();
        RDDisassembler* disassembler();
        void bindDisassembler(RDDisassembler* disassembler);
        void hideActions();
        void toggleFilter();
        void showFilter();
        void clearFilter();

    public slots:
        void showGoto();
        void goForward();
        void goBack();

    private slots:
        void checkDisassemblerStatus();
        void modelIndexSelected(const QModelIndex& index);
        void checkHexEdit(int index);
        void updateCurrentFilter(int index);
        void gotoXRef(const QModelIndex &index);
        void goTo(const QModelIndex &index);
        void showModelReferences();
        void showCurrentItemInfo();
        void showReferences(address_t address);
        void displayAddress(address_t address);
        void displayCurrentReferences();
        void switchGraphListing();
        void switchToHexDump();
        void selectToHexDump(address_t address, u64 len);
        void showMenu(const QPoint&);

    private:
        bool itemFromIndex(const QModelIndex& index, RDDocumentItem* item) const;
        ListingFilterModel* getSelectedFilterModel();
        QString currentWord() const;
        RDCursor* activeCursor() const;
        bool getCurrentItem(RDDocumentItem* item) const;
        void showListingOrGraph();
        void createActions();
        void filterSymbols();
        void syncHexEdit();

    private:
        Ui::DisassemblerView *ui;
        RDDisassembler* m_disassembler{nullptr};
        DisassemblerViewActions* m_actions;
        DisassemblerViewDocks* m_docks;
        DisassemblerGraphView* m_graphview;
        DisassemblerListingView* m_listingview;
        QModelIndex m_currentindex;
        QHexDocument* m_hexdocument;
        QMenu* m_contextmenu;
        QLineEdit* m_lefilter;
        ListingFilterModel *m_segmentsmodel, *m_importsmodel, *m_exportsmodel, *m_stringsmodel;
        QAction* m_actsetfilter;
};
