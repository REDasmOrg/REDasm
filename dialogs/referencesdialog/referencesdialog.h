#pragma once

#include <QDialog>
#include "../../models/referencesmodel.h"
#include "../../hooks/icommand.h"

namespace Ui {
class ReferencesDialog;
}

class ReferencesDialog : public QDialog
{
    Q_OBJECT

    public:
        explicit ReferencesDialog(ICommand* command, const RDSymbol *symbol, QWidget *parent = nullptr);
        ~ReferencesDialog();

    private slots:
        void on_tvReferences_doubleClicked(const QModelIndex &index);

    private:
        Ui::ReferencesDialog *ui;
        ReferencesModel* m_referencesmodel;
        ICommand* m_command;
};
