#include "blockstab.h"
#include "ui_blockstab.h"
#include "../../../models/dev/blocklistmodel.h"

BlocksTab::BlocksTab(QWidget *parent) : QWidget(parent), ui(new Ui::BlocksTab)
{
    ui->setupUi(this);
    ui->splitter->setStretchFactor(1, 1);
}

BlocksTab::~BlocksTab() { delete ui; }

void BlocksTab::setContext(const RDContextPtr& ctx)
{
    m_context = ctx;
    if(m_segmentsmodel) m_segmentsmodel->deleteLater();

    m_segmentsmodel = new SegmentsModel(ui->tvSegments);
    m_segmentsmodel->setContext(ctx);

    ui->tvSegments->setModel(m_segmentsmodel);
    ui->tvSegments->header()->moveSection(7, 0);

    for(int i = 2; i < ui->tvSegments->model()->columnCount() - 1; i++) // Hide other columns
        ui->tvSegments->header()->hideSection(i);

    connect(ui->tvSegments->selectionModel(), &QItemSelectionModel::currentChanged, this, &BlocksTab::showBlocks);
    ui->tvSegments->setCurrentIndex(m_segmentsmodel->index(0));
}

void BlocksTab::showBlocks(const QModelIndex& current, const QModelIndex&)
{
    if(!current.isValid()) return;
    RDDocument* doc = RDContext_GetDocument(m_context.get());

    const RDDocumentItem& item = m_segmentsmodel->item(current);
    RDSegment segment;

    if(RDDocument_GetSegmentAddress(doc, item.address, &segment))
        ui->tableWidget->setModel(new BlockListModel(m_context, RDDocument_GetBlocks(doc, segment.address)));
    else
        ui->tableWidget->setModel(new BlockListModel(m_context, nullptr));
}
