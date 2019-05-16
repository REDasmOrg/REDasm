#ifndef GOTODIALOG_H
#define GOTODIALOG_H

#include <QDialog>
#include <redasm/disassembler/disassemblerapi.h>
#include "../../models/gotomodel/gotofiltermodel.h"

namespace Ui {
class GotoDialog;
}

class GotoDialog : public QDialog
{
    Q_OBJECT

    public:
        explicit GotoDialog(const REDasm::DisassemblerPtr &disassembler, QWidget *parent = nullptr);
        bool hasValidAddress() const;
        address_t address() const;
        ~GotoDialog();

    private:
        void validateEntry();

    private slots:
        void onItemSelected(const QModelIndex& index);

    signals:
        void gotoAddress(address_t address);
        void symbolSelected(const QModelIndex& index);

    private:
        Ui::GotoDialog *ui;
        REDasm::DisassemblerPtr m_disassembler;
        GotoFilterModel* m_gotomodel;
        address_t m_address;
        bool m_validaddress;
};

#endif // GOTODIALOG_H
