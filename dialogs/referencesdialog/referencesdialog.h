#pragma once

#include <QDialog>
#include "../../models/referencesmodel.h"

namespace Ui {
class ReferencesDialog;
}

class ReferencesDialog : public QDialog
{
    Q_OBJECT

    public:
        explicit ReferencesDialog(const RDContextPtr& ctx, ISurface* surface, rd_address address, QWidget *parent = nullptr);
        ~ReferencesDialog();

    private Q_SLOTS:
        void on_tvReferences_doubleClicked(const QModelIndex &index);

    private:
        Ui::ReferencesDialog *ui;
        RDContextPtr m_context;
        ISurface* m_surface;
        ReferencesModel* m_referencesmodel;
};
