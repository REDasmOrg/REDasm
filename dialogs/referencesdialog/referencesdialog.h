#ifndef REFERENCESDIALOG_H
#define REFERENCESDIALOG_H

#include <QDialog>
#include "../../models/referencesmodel.h"

namespace Ui {
class ReferencesDialog;
}

class ReferencesDialog : public QDialog
{
    Q_OBJECT

    public:
        explicit ReferencesDialog(const REDasm::DisassemblerPtr& disassembler, const REDasm::Symbol *symbol, QWidget *parent = nullptr);
        ~ReferencesDialog();

    signals:
        void jumpTo(address_t address);

    private slots:
        void on_tvReferences_doubleClicked(const QModelIndex &index);

    private:
        Ui::ReferencesDialog *ui;
        ReferencesModel* m_referencesmodel;
};

#endif // REFERENCESDIALOG_H
