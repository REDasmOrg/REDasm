#include "referencesdialog.h"
#include "ui_referencesdialog.h"
#include <core/disassembler/listing/listingdocument.h>

ReferencesDialog::ReferencesDialog(const REDasm::DisassemblerPtr& disassembler, const REDasm::Symbol* symbol, QWidget *parent) : QDialog(parent), ui(new Ui::ReferencesDialog)
{
    ui->setupUi(this);

    this->setWindowTitle(QString("%1 References").arg(QString::fromStdString(symbol->name)));

    m_referencesmodel = new ReferencesModel(ui->tvReferences);
    m_referencesmodel->setDisassembler(disassembler);
    m_referencesmodel->xref(symbol->address);

    ui->tvReferences->setModel(m_referencesmodel);
}

ReferencesDialog::~ReferencesDialog() { delete ui; }

void ReferencesDialog::on_tvReferences_doubleClicked(const QModelIndex &index)
{
    if(!index.isValid() || !index.internalId())
        return;

    emit jumpTo(index.internalId());
    this->accept();
}
