#ifndef SIGNATURESDIALOG_H
#define SIGNATURESDIALOG_H

#include <QSortFilterProxyModel>
#include <QDialog>
#include "../models/signatures/signaturefilesmodel.h"
#include "../models/signatures/signaturesmodel.h"
#include <core/disassembler/disassemblerapi.h>

namespace Ui {
class SignaturesDialog;
}

class SignaturesDialog : public QDialog
{
    Q_OBJECT

    public:
        explicit SignaturesDialog(REDasm::DisassemblerAPI* disassembler, QWidget *parent = nullptr);
        ~SignaturesDialog();

    private slots:
        void loadSignature(bool);
        void readSignature(const QModelIndex& index);
        void browseSignatures();

    private:
        Ui::SignaturesDialog *ui;
        REDasm::DisassemblerAPI* m_disassembler;
        SignatureFilesModel* m_signaturefilesmodel;
        SignaturesModel* m_signaturesmodel;
        QSortFilterProxyModel* m_filtermodel;
};

#endif // SIGNATURESDIALOG_H
