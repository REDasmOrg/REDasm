#include "referencesdialog.h"
#include "ui_referencesdialog.h"
#include "../../hooks/disassemblerhooks.h"
#include "../../renderer/surfaceqt.h"

ReferencesDialog::ReferencesDialog(const RDContextPtr& ctx, const RDSymbol* symbol, QWidget *parent) : QDialog(parent), ui(new Ui::ReferencesDialog), m_context(ctx)
{
    ui->setupUi(this);

    RDDocument* doc = RDContext_GetDocument(ctx.get());
    this->setWindowTitle(QString("%1 References").arg(RDDocument_GetSymbolName(doc, symbol->address)));

    m_referencesmodel = new ReferencesModel(ui->tvReferences);
    m_referencesmodel->setContext(ctx);
    m_referencesmodel->xref(symbol->address);

    ui->tvReferences->setModel(m_referencesmodel);
}

ReferencesDialog::~ReferencesDialog() { delete ui; }

void ReferencesDialog::on_tvReferences_doubleClicked(const QModelIndex &index)
{
    if(!index.isValid() || !index.internalId())
        return;

    auto* surface = DisassemblerHooks::instance()->activeSurface();
    if(surface) surface->goToAddress(static_cast<rd_address>(index.internalId()));
    this->accept();
}
