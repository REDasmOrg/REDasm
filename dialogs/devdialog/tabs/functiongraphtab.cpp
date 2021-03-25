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

    m_functionsmodel = new FunctionsModel(ctx, ui->tbvFunctions);

    m_functiongraphmodel = new FunctionGraphModel(ctx, ui->tbvGraph);
    m_sortedblocksmodel = new QSortFilterProxyModel(ui->tbvGraph);
    m_sortedblocksmodel->setSourceModel(m_functiongraphmodel);
    m_sortedblocksmodel->setSortRole(Qt::UserRole);

    ui->tbvFunctions->setModel(m_functionsmodel);
    ui->tbvGraph->setModel(m_sortedblocksmodel);

    ui->tbvFunctions->verticalHeader()->setDefaultSectionSize(ui->tbvFunctions->verticalHeader()->minimumSectionSize());
    ui->tbvFunctions->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    ui->tbvFunctions->horizontalHeader()->setSectionResizeMode(1, QHeaderView::Stretch);

    ui->tbvGraph->verticalHeader()->setDefaultSectionSize(ui->tbvFunctions->verticalHeader()->minimumSectionSize());
    ui->tbvGraph->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);

    connect(ui->tbvFunctions->selectionModel(), &QItemSelectionModel::currentChanged, this, &FunctionGraphTab::showGraph);
    connect(ui->pbCopyUnitTest, &QPushButton::clicked, this, &FunctionGraphTab::copyUnitTests);
    connect(ui->pbCopyGraph, &QPushButton::clicked, this, &FunctionGraphTab::copyGraph);
    connect(ui->pbCopyHash, &QPushButton::clicked, this, &FunctionGraphTab::copyHash);
}

void FunctionGraphTab::showGraph(const QModelIndex& current, const QModelIndex&)
{
    auto* graph = this->getGraph(current);
    if(!graph) return;

    m_functiongraphmodel->setGraph(graph);
    m_sortedblocksmodel->sort(0);
}

void FunctionGraphTab::copyUnitTests() const
{
    QString s = "{\n";

    for(int i = 0; i < m_functionsmodel->rowCount(); i++)
    {
        QModelIndex index = m_functionsmodel->index(i);
        if(!index.isValid()) continue;

        auto* graph = this->getGraph(index);
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

const RDGraph* FunctionGraphTab::getGraph(const QModelIndex& index) const
{
    RDDocument* doc = RDContext_GetDocument(m_functionsmodel->context().get());
    rd_address address = m_functionsmodel->address(index);

    RDGraph* graph;
    return RDDocument_GetFunctionGraph(doc, address, &graph) ? graph : nullptr;
}

const RDGraph* FunctionGraphTab::getSelectedGraph() const { return this->getGraph(ui->tbvFunctions->currentIndex()); }
