#include "blockstab.h"
#include "ui_blockstab.h"
#include "../../../models/dev/blocklistmodel.h"

BlocksTab::BlocksTab(QWidget *parent) : QWidget(parent), ui(new Ui::BlocksTab)
{
    ui->setupUi(this);
    ui->splitter->setStretchFactor(1, 1);
}

BlocksTab::~BlocksTab() { delete ui; }

void BlocksTab::setCommand(ICommand* command)
{
    m_command = command;
    if(m_segmentsmodel) m_segmentsmodel->deleteLater();

    m_segmentsmodel = new SegmentsModel(ui->tvSegments);
    m_segmentsmodel->setContext(command->context());

    ui->tvSegments->setModel(m_segmentsmodel);
    ui->tvSegments->header()->moveSection(8, 0);

    for(int i = 2; i < 8; i++) // Hide other columns
        ui->tvSegments->header()->hideSection(i);

    connect(ui->tvSegments->selectionModel(), &QItemSelectionModel::currentChanged, this, &BlocksTab::showBlocks);
    ui->tvSegments->setCurrentIndex(m_segmentsmodel->index(0));
}

void BlocksTab::showBlocks(const QModelIndex& current, const QModelIndex&)
{
    if(!current.isValid()) return;
    RDDocument* doc = RDContext_GetDocument(m_command->context().get());

    RDSegment segment;

    if(RDDocument_GetSegmentAt(doc, current.row(), &segment))
        ui->tableWidget->setModel(new BlockListModel(m_command, RDDocument_GetBlocks(doc, segment.address)));
    else
        ui->tableWidget->setModel(new BlockListModel(m_command, nullptr));
}
