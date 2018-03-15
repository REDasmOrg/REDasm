#ifndef CALLGRAPHDIALOG_H
#define CALLGRAPHDIALOG_H

#include <QDialog>
#include "../../redasm/disassembler/disassembler.h"

namespace Ui {
class CallGraphDialog;
}

class CallGraphDialog : public QDialog
{
    Q_OBJECT

    public:
        explicit CallGraphDialog(address_t address, REDasm::Disassembler* disassembler, QWidget *parent = 0);
        ~CallGraphDialog();

    private:
        Ui::CallGraphDialog *ui;
        REDasm::Disassembler* _disassembler;
};

#endif // CALLGRAPHDIALOG_H
