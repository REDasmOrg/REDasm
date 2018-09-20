#ifndef CALLGRAPHDIALOG_H
#define CALLGRAPHDIALOG_H

#include <QDialog>
#include "../../redasm/disassembler/disassemblerapi.h"

namespace Ui {
class CallGraphDialog;
}

class CallGraphDialog : public QDialog
{
    Q_OBJECT

    public:
        explicit CallGraphDialog(address_t address, REDasm::DisassemblerAPI* disassembler, QWidget *parent = 0);
        ~CallGraphDialog();

    private:
        Ui::CallGraphDialog *ui;
        REDasm::DisassemblerAPI* m_disassembler;
};

#endif // CALLGRAPHDIALOG_H
