#include "functiongraphtab.h"
#include "ui_functiongraphtab.h"
#include <QApplication>
#include <QClipboard>

FunctionGraphTab::FunctionGraphTab(QWidget *parent) : QWidget(parent), ui(new Ui::FunctionGraphTab) { ui->setupUi(this); }
FunctionGraphTab::~FunctionGraphTab() { delete ui; }

void FunctionGraphTab::setContext(const RDContextPtr& ctx)
{
    if(ui->tbvFunctions->selectionModel())
        disconnect(ui->tbvFunctions->selectionModel(), &QItemSelectionModel::currentChanged, this, nullptr);

    m_functionlistmodel = new FunctionListModel(ui->tbvFunctions);
    m_functionlistmodel->setContext(ctx);

    m_functiongraphmodel = new FunctionGraphModel(ctx, ui->tbvGraph);
    m_sortedblocksmodel = new QSortFilterProxyModel(ui->tbvGraph);
    m_sortedblocksmodel->setSourceModel(m_functiongraphmodel);
    m_sortedblocksmodel->setSortRole(Qt::UserRole);

    ui->tbvFunctions->setModel(m_functionlistmodel);
    ui->tbvGraph->setModel(m_sortedblocksmodel);

    ui->tbvFunctions->verticalHeader()->setDefaultSectionSize(ui->tbvFunctions->verticalHeader()->minimumSectionSize());
    ui->tbvFunctions->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    ui->tbvFunctions->horizontalHeader()->setSectionResizeMode(1, QHeaderView::Stretch);
    ui->tbvFunctions->horizontalHeader()->setSectionResizeMode(3, QHeaderView::Stretch);
    ui->tbvFunctions->horizontalHeader()->moveSection(3, 1);
    ui->tbvFunctions->horizontalHeader()->hideSection(2);

    ui->tbvGraph->verticalHeader()->setDefaultSectionSize(ui->tbvFunctions->verticalHeader()->minimumSectionSize());
    ui->tbvGraph->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);

    connect(ui->tbvFunctions->selectionModel(), &QItemSelectionModel::currentChanged, this, &FunctionGraphTab::showGraph);
    connect(ui->pbCopyUnitTest, &QPushButton::clicked, this, &FunctionGraphTab::copyUnitTests);
    connect(ui->pbCopyGraph, &QPushButton::clicked, this, &FunctionGraphTab::copyGraph);
    connect(ui->pbCopyHash, &QPushButton::clicked, this, &FunctionGraphTab::copyHash);
}

void FunctionGraphTab::showGraph(const QModelIndex& current, const QModelIndex&)
{
    const RDGraph* graph = m_functionlistmodel->graph(current);
    m_functiongraphmodel->setGraph(graph);
    m_sortedblocksmodel->sort(0);
}

void FunctionGraphTab::copyUnitTests() const
{
    QString s = "{\n";

    for(int i = 0; i < m_functionlistmodel->rowCount(); i++)
    {
        QModelIndex index = m_functionlistmodel->index(i);
        if(!index.isValid()) continue;

        const RDGraph* graph = m_functionlistmodel->graph(index);
        if(!graph) continue;

        rd_address startaddress = RDFunctionGraph_GetStartAddress(graph);
        u32 hash = RDGraph_Hash(graph);

        s += QString("\t{ %1, %2 },\n").arg(QString::fromUtf8(RD_ToHexBits(startaddress, 0, true)),
                                            QString::fromUtf8(RD_ToHexBits(hash, 32, true)));
    }

    s += "};";
    qApp->clipboard()->setText(s);
}

void FunctionGraphTab::copyGraph() const
{
    const RDGraph* graph = this->getSelectedGraph();
    qApp->clipboard()->setText(RDGraph_GenerateDOT(graph));
}

void FunctionGraphTab::copyHash() const
{
    const RDGraph* graph = this->getSelectedGraph();
    qApp->clipboard()->setText(RD_ToHexBits(RDGraph_Hash(graph), 32, true));
}

const RDGraph* FunctionGraphTab::getSelectedGraph() const
{
    QModelIndex index = ui->tbvFunctions->currentIndex();
    return index.isValid() ? m_functionlistmodel->graph(index) : nullptr;
}
