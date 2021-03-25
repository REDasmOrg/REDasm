#include "blockstab.h"
#include "ui_blockstab.h"
#include "../../../models/dev/blocklistmodel.h"

BlocksTab::BlocksTab(QWidget *parent) : QWidget(parent), ui(new Ui::BlocksTab)
{
    ui->setupUi(this);
    ui->splitter->setStretchFactor(1, 1);
    ui->tableWidget->setAlternatingRowColors(true);
}

BlocksTab::~BlocksTab() { delete ui; }

void BlocksTab::setContext(const RDContextPtr& ctx)
{
    m_context = ctx;
    if(m_segmentsmodel) m_segmentsmodel->deleteLater();

    m_segmentsmodel = new SegmentsModel(m_context, ui->tvSegments);
    ui->tvSegments->setModel(m_segmentsmodel);
    connect(ui->tvSegments->selectionModel(), &QItemSelectionModel::currentChanged, this, &BlocksTab::showBlocks);
}

void BlocksTab::showBlocks(const QModelIndex& current, const QModelIndex&)
{
    if(!current.isValid()) return;
    RDDocument* doc = RDContext_GetDocument(m_context.get());

    rd_address address = m_segmentsmodel->address(current);
    RDSegment segment;

    if(RDDocument_AddressToSegment(doc, address, &segment))
        ui->tableWidget->setModel(new BlockListModel(m_context, segment.address));
    else
        ui->tableWidget->setModel(new BlockListModel(m_context, RD_NVAL));

    ui->tableWidget->resizeColumnsUntil(-1);
}
