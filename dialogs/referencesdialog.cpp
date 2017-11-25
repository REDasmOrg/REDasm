#include "referencesdialog.h"
#include "ui_referencesdialog.h"

ReferencesDialog::ReferencesDialog(REDasm::Disassembler *disassembler, address_t currentaddress, REDasm::Symbol *symbol, QWidget *parent) : QDialog(parent), ui(new Ui::ReferencesDialog)
{
    ui->setupUi(this);
    this->setWindowTitle(QString("%1 References").arg(QString::fromStdString(symbol->name)));

    this->_referencesmodel = new ReferencesModel(disassembler, ui->tvReferences);
    this->_referencesmodel->xref(currentaddress, symbol);

    ui->tvReferences->setModel(this->_referencesmodel);
}

ReferencesDialog::~ReferencesDialog()
{
    delete ui;
}

void ReferencesDialog::on_tvReferences_doubleClicked(const QModelIndex &index)
{
    if(!index.isValid() || !index.internalPointer())
        return;

    REDasm::Instruction* instruction = reinterpret_cast<REDasm::Instruction*>(index.internalPointer());
    emit jumpTo(instruction->address);
    this->accept();
}
