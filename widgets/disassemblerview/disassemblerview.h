#ifndef DISASSEMBLERVIEW_H
#define DISASSEMBLERVIEW_H

#include <QWidget>
#include <QLabel>
#include <QMenu>
#include <qhexedit.h>
#include "../../models/listingfiltermodel.h"
#include "../../models/symboltablemodel.h"
#include "../../models/referencesmodel.h"
#include "../../models/segmentsmodel.h"
#include "../../dialogs/gotodialog.h"
#include "../../redasm/disassembler/disassembler.h"

namespace Ui {
class DisassemblerView;
}

class DisassemblerView : public QWidget
{
    Q_OBJECT

    public:
        explicit DisassemblerView(QLabel* lblstatus, QPushButton* pbstatus, QWidget *parent = 0);
        ~DisassemblerView();
        void setDisassembler(REDasm::Disassembler* disassembler);

    private slots:
        void on_topTabs_currentChanged(int index);
        void on_bottomTabs_currentChanged(int index);
        void gotoXRef(const QModelIndex &index);
        void gotoSymbol(const QModelIndex &index);
        void xrefSymbol(const QModelIndex &index);
        void displayAddress(address_t address);
        void displayCurrentReferences();
        void updateModel(const REDasm::SymbolPtr& symbol);
        void log(const QString& s);
        void filterFunctions();
        void filterSymbols();
        void onDisassemblerBusyChanged();
        void showHexDump(address_t address);
        void showMenu(const QPoint&);
        void showGoto();

    private:
        void createMenu();

    private:
        Ui::DisassemblerView *ui;
        QModelIndex m_currentindex;
        QHexDocument* m_hexdocument;
        QMenu* m_contextmenu;
        QLabel* m_lblstatus;
        QPushButton* m_pbstatus;
        REDasm::Disassembler* m_disassembler;
        ListingFilterModel *m_segmentsmodel, *m_functionsmodel, *m_importsmodel, *m_exportsmodel, *m_stringsmodel;
        ReferencesModel* m_referencesmodel;
};

#endif // DISASSEMBLERVIEW_H
