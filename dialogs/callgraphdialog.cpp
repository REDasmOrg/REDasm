#include "callgraphdialog.h"
#include "ui_callgraphdialog.h"

CallGraphDialog::CallGraphDialog(address_t address, REDasm::Disassembler *disassembler, QWidget *parent) : QDialog(parent), ui(new Ui::CallGraphDialog), _disassembler(disassembler)
{
    ui->setupUi(this);

    REDasm::SymbolTable* symboltable = disassembler->symbolTable();
    REDasm::SymbolPtr symbol = symboltable->symbol(address);

    this->setWindowTitle(QString("Callgraph of %1").arg(QString::fromStdString(symbol ? symbol->name : REDasm::hex(address))));
    ui->callGraphView->display(address, disassembler);
}

CallGraphDialog::~CallGraphDialog()
{
    delete ui;
}
