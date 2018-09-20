#include "callgraphdialog.h"
#include "ui_callgraphdialog.h"

CallGraphDialog::CallGraphDialog(address_t address, REDasm::DisassemblerAPI *disassembler, QWidget *parent) : QDialog(parent), ui(new Ui::CallGraphDialog), m_disassembler(disassembler)
{
    ui->setupUi(this);
    this->setWindowTitle(QString("Callgraph of %1").arg(QString::fromStdString(REDasm::hex(address))));
    ui->callGraphView->display(address, disassembler);
}

CallGraphDialog::~CallGraphDialog()
{
    delete ui;
}
