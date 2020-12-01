#include "rdiltab.h"
#include "ui_rdiltab.h"
#include "../../../renderer/surfaceqt.h"

RDILTab::RDILTab(QWidget *parent) : QWidget(parent), ui(new Ui::RDILTab) { ui->setupUi(this); }
RDILTab::~RDILTab() { delete ui; }

void RDILTab::setContext(const RDContextPtr& ctx)
{
    m_context = ctx;
    this->updateInformation();
}

void RDILTab::updateInformation()
{
    RDDocumentItem item;
    const SurfaceQt* surface = nullptr;

    auto* activesurface = RDContext_GetActiveSurface(m_context.get());
    if(!activesurface) goto notitle;

    surface = reinterpret_cast<const SurfaceQt*>(RDSurface_GetUserData(activesurface));
    if(!surface->getCurrentItem(&item)) goto notitle;

    ui->lblTitle->setText(RD_GetInstruction(m_context.get(), item.address));
    m_graph.reset(RDILGraph_Create(m_context.get(), item.address));
    ui->graphView->setGraph(m_graph.get());
    return;

notitle:
    ui->lblTitle->clear();
}
