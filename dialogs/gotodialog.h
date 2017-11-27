#ifndef GOTODIALOG_H
#define GOTODIALOG_H

#include <QDialog>
#include "../redasm/disassembler/disassembler.h"
#include "../models/symboltablefiltermodel.h"

namespace Ui {
class GotoDialog;
}

class GotoDialog : public QDialog
{
    Q_OBJECT

    public:
        explicit GotoDialog(REDasm::Disassembler* disassembler, QWidget *parent = 0);
        address_t address() const;
        ~GotoDialog();

    private:
        void validateEntry();

    signals:
        void gotoAddress(address_t address);
        void symbolSelected(const QModelIndex& index);

    private:
        Ui::GotoDialog *ui;
        REDasm::Disassembler* _disassembler;
        SymbolTableFilterModel* _functionsmodel;
        address_t _address;
};

#endif // GOTODIALOG_H
