#include "referencesdialog.h"
#include "ui_referencesdialog.h"

ReferencesDialog::ReferencesDialog(ICommand* command, const RDSymbol* symbol, QWidget *parent) : QDialog(parent), ui(new Ui::ReferencesDialog), m_command(command)
{
    ui->setupUi(this);

    RDDocument* doc = RDContext_GetDocument(command->context().get());
    this->setWindowTitle(QString("%1 References").arg(RDDocument_GetSymbolName(doc, symbol->address)));

    m_referencesmodel = new ReferencesModel(command, ui->tvReferences);
    m_referencesmodel->setContext(command->context());
    m_referencesmodel->xref(symbol->address);

    ui->tvReferences->setModel(m_referencesmodel);
}

ReferencesDialog::~ReferencesDialog() { delete ui; }

void ReferencesDialog::on_tvReferences_doubleClicked(const QModelIndex &index)
{
    if(!index.isValid() || !index.internalId())
        return;

    m_command->goToAddress(static_cast<rd_address>(index.internalId()));
    this->accept();
}
