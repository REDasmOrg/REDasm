#include "referencesdialog.h"
#include "ui_referencesdialog.h"

ReferencesDialog::ReferencesDialog(IDisassemblerCommand* command, const RDSymbol* symbol, QWidget *parent) : QDialog(parent), ui(new Ui::ReferencesDialog), m_command(command)
{
    ui->setupUi(this);

    RDDocument* doc = RDDisassembler_GetDocument(command->disassembler());
    this->setWindowTitle(QString("%1 References").arg(RDDocument_GetSymbolName(doc, symbol->address)));

    m_referencesmodel = new ReferencesModel(command, ui->tvReferences);
    m_referencesmodel->setDisassembler(command->disassembler());
    m_referencesmodel->xref(symbol->address);

    ui->tvReferences->setModel(m_referencesmodel);
}

ReferencesDialog::~ReferencesDialog() { delete ui; }

void ReferencesDialog::on_tvReferences_doubleClicked(const QModelIndex &index)
{
    if(!index.isValid() || !index.internalId())
        return;

    m_command->gotoAddress(static_cast<rd_address>(index.internalId()));
    this->accept();
}
