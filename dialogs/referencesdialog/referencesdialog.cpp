#include "referencesdialog.h"
#include "ui_referencesdialog.h"
#include "../../hooks/disassemblerhooks.h"
#include "../../renderer/surfaceqt.h"

ReferencesDialog::ReferencesDialog(const RDContextPtr& ctx, ISurface* surface, rd_address address, QWidget *parent) : QDialog(parent), ui(new Ui::ReferencesDialog), m_context(ctx), m_surface(surface)
{
    ui->setupUi(this);

    RDDocument* doc = RDContext_GetDocument(ctx.get());
    this->setWindowTitle(QString("%1 References").arg(RDDocument_GetLabel(doc, address)));

    m_referencesmodel = new ReferencesModel(ui->tvReferences);
    m_referencesmodel->setContext(ctx);
    m_referencesmodel->xref(address);

    ui->tvReferences->setModel(m_referencesmodel);
    ui->tvReferences->horizontalHeader()->setStretchLastSection(true);
}

ReferencesDialog::~ReferencesDialog() { delete ui; }

void ReferencesDialog::on_tvReferences_doubleClicked(const QModelIndex &index)
{
    if(!index.isValid() || !index.internalId()) return;
    m_surface->goTo(static_cast<rd_address>(index.internalId()));
    this->accept();
}
