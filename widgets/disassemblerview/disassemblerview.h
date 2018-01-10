#ifndef DISASSEMBLERVIEW_H
#define DISASSEMBLERVIEW_H

#include <QWidget>
#include <QLabel>
#include <qhexedit.h>
#include "../../models/symboltablefiltermodel.h"
#include "../../models/referencesmodel.h"
#include "../../models/segmentsmodel.h"
#include "../../dialogs/gotodialog.h"
#include "../../redasm/disassembler/disassembler.h"
#include "disassemblerthread.h"

namespace Ui {
class DisassemblerView;
}

class DisassemblerView : public QWidget
{
    Q_OBJECT

    public:
        explicit DisassemblerView(QLabel* lblstatus, QWidget *parent = 0);
        ~DisassemblerView();
        void setDisassembler(REDasm::Disassembler* disassembler);
        bool busy() const;

    private slots:
        void on_topTabs_currentChanged(int index);
        void on_bottomTabs_currentChanged(int index);
        void seekToXRef(const QModelIndex &index);
        void seekToSymbol(const QModelIndex &index);
        void xrefSymbol(const QModelIndex &index);
        void displayAddress(address_t address);
        void displayInstructionReferences();
        void displayReferences();
        void updateModel(const REDasm::SymbolPtr& symbol);
        void log(const QString& s);
        void filterFunctions();
        void filterSymbols();
        void showListing();
        void showHexDump(address_t address);
        void showGoto();

    signals:
        void done();

    private:
        Ui::DisassemblerView *ui;
        QHexDocument* _hexdocument;
        QLabel* _lblstatus;
        REDasm::Disassembler* _disassembler;
        DisassemblerThread* _disassemblerthread;
        SymbolTableFilterModel *_functionsmodel, *_importsmodel, *_exportsmodel, *_stringsmodel;
        ReferencesModel* _referencesmodel;
        SegmentsModel* _segmentsmodel;
};

#endif // DISASSEMBLERVIEW_H
