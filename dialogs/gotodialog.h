#ifndef GOTODIALOG_H
#define GOTODIALOG_H

#include <QDialog>
#include <redasm/disassembler/disassemblerapi.h>
#include "../models/listingfiltermodel.h"

namespace Ui {
class GotoDialog;
}

class GotoDialog : public QDialog
{
    Q_OBJECT

    public:
        explicit GotoDialog(REDasm::DisassemblerAPI* disassembler, QWidget *parent = 0);
        address_t address() const;
        ~GotoDialog();

    private:
        void validateEntry();

    signals:
        void gotoAddress(address_t address);
        void symbolSelected(const QModelIndex& index);

    private:
        Ui::GotoDialog *ui;
        REDasm::DisassemblerAPI* m_disassembler;
        ListingFilterModel* m_functionsmodel;
        address_t m_address;
};

#endif // GOTODIALOG_H
