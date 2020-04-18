#include "referencesdialog.h"
#include "ui_referencesdialog.h"

ReferencesDialog::ReferencesDialog(RDDisassembler* disassembler, const RDSymbol* symbol, const RDCursor* cursor, QWidget *parent) : QDialog(parent), ui(new Ui::ReferencesDialog)
{
    ui->setupUi(this);

    RDDocument* doc = RDDisassembler_GetDocument(disassembler);
    this->setWindowTitle(QString("%1 References").arg(RDDocument_GetSymbolName(doc, symbol->address)));

    m_referencesmodel = new ReferencesModel(ui->tvReferences);
    m_referencesmodel->setDisassembler(disassembler);
    m_referencesmodel->xref(symbol->address, cursor);

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
