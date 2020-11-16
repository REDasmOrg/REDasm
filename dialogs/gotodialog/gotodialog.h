#pragma once

#include <QDialog>
#include <rdapi/rdapi.h>
#include "../../models/gotomodel/gotofiltermodel.h"

namespace Ui {
class GotoDialog;
}

class GotoDialog : public QDialog
{
    Q_OBJECT

    public:
        explicit GotoDialog(const RDContextPtr& ctx, QWidget *parent = nullptr);
        ~GotoDialog();

    private:
        bool hasValidAddress() const;
        void validateEntry();

    private slots:
        void onGotoClicked();
        void onItemSelected(const QModelIndex& index);

    private:
        Ui::GotoDialog *ui;
        RDContextPtr m_context;
        RDDocument* m_document;
        GotoFilterModel* m_gotomodel;
        rd_address m_address{0};
        bool m_validaddress{false};
};
