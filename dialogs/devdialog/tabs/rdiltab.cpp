#include "rdiltab.h"
#include "ui_rdiltab.h"

RDILTab::RDILTab(QWidget *parent) : QWidget(parent), ui(new Ui::RDILTab) { ui->setupUi(this); }
RDILTab::~RDILTab() { delete ui; }

void RDILTab::setCommand(IDisassemblerCommand* command)
{
    m_command = command;
    m_renderer.reset(RDRenderer_Create(m_command->disassembler().get(), nullptr, RendererFlags_Normal));
    this->updateInformation();
}

void RDILTab::updateInformation()
{
    RDDocumentItem item;

    if(!m_command->getCurrentItem(&item))
    {
        ui->lblTitle->clear();
        return;
    }

    ui->lblTitle->setText(RDRenderer_GetInstruction(m_renderer.get(), item.address));

    m_graph.reset(RDILGraph_Create(m_command->disassembler().get(), item.address));
    ui->graphView->setGraph(m_graph.get());
}
