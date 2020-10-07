#pragma once

#include <QSortFilterProxyModel>
#include <QDialog>
#include <rdapi/rdapi.h>
#include "../hooks/icommand.h"
#include "../models/signatures/signaturefilesmodel.h"
#include "../models/signatures/signaturesmodel.h"

namespace Ui {
class SignaturesDialog;
}

class SignaturesDialog : public QDialog
{
    Q_OBJECT

    public:
        explicit SignaturesDialog(const RDContextPtr& ctx, QWidget *parent = nullptr);
        ~SignaturesDialog();

    private slots:
        void loadSignature(bool);
        void readSignature(const QModelIndex& index);
        void browseSignatures();

    private:
        Ui::SignaturesDialog *ui;
        RDContextPtr m_context;
        SignatureFilesModel* m_signaturefilesmodel;
        SignaturesModel* m_signaturesmodel;
        QSortFilterProxyModel* m_filtermodel;
};
