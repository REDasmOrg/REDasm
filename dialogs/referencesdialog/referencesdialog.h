#pragma once

#include <QDialog>
#include "../../models/referencesmodel.h"
#include "../../hooks/idisassemblercommand.h"

namespace Ui {
class ReferencesDialog;
}

class ReferencesDialog : public QDialog
{
    Q_OBJECT

    public:
        explicit ReferencesDialog(IDisassemblerCommand* command, const RDSymbol *symbol, QWidget *parent = nullptr);
        ~ReferencesDialog();

    signals:
        void jumpTo(address_t address);

    private slots:
        void on_tvReferences_doubleClicked(const QModelIndex &index);

    private:
        Ui::ReferencesDialog *ui;
        ReferencesModel* m_referencesmodel;
};
