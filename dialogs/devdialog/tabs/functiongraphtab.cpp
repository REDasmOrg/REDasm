#include "functiongraphtab.h"
#include "ui_functiongraphtab.h"
#include <QApplication>
#include <QClipboard>

FunctionGraphTab::FunctionGraphTab(QWidget *parent) : QWidget(parent), ui(new Ui::FunctionGraphTab)
{
    ui->setupUi(this);
    ui->splitter->setStretchFactor(1, 1);
}

FunctionGraphTab::~FunctionGraphTab() { delete ui; }

void FunctionGraphTab::setCommand(IDisassemblerCommand* command)
{
    if(ui->tbvFunctions->selectionMode())
        disconnect(ui->tbvFunctions->selectionModel(), &QItemSelectionModel::currentChanged, this, nullptr);

    m_functionlistmodel = new FunctionListModel(ui->tbvFunctions);
    m_functionlistmodel->setDisassembler(command->disassembler());

    m_functiongraphmodel = new FunctionGraphModel(command->disassembler(), ui->tbvGraph);
    m_sortedblocksmodel = new QSortFilterProxyModel(ui->tbvGraph);
    m_sortedblocksmodel->setSourceModel(m_functiongraphmodel);
    m_sortedblocksmodel->setSortRole(Qt::UserRole);

    ui->tbvFunctions->setModel(m_functionlistmodel);
    ui->tbvGraph->setModel(m_sortedblocksmodel);

    ui->tbvFunctions->verticalHeader()->setDefaultSectionSize(ui->tbvFunctions->verticalHeader()->minimumSectionSize());
    ui->tbvFunctions->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    ui->tbvFunctions->horizontalHeader()->setSectionResizeMode(1, QHeaderView::Stretch);
    ui->tbvFunctions->horizontalHeader()->hideSection(2);
    ui->tbvFunctions->horizontalHeader()->hideSection(3);

    ui->tbvGraph->verticalHeader()->setDefaultSectionSize(ui->tbvFunctions->verticalHeader()->minimumSectionSize());
    ui->tbvGraph->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);

    connect(ui->tbvFunctions->selectionModel(), &QItemSelectionModel::currentChanged, this, &FunctionGraphTab::showGraph);
    connect(ui->pbCopyGraph, &QPushButton::clicked, this, &FunctionGraphTab::copyGraph);
    connect(ui->pbCopyHash, &QPushButton::clicked, this, &FunctionGraphTab::copyHash);
}

void FunctionGraphTab::showGraph(const QModelIndex& current, const QModelIndex&)
{
    const RDGraph* graph = m_functionlistmodel->graph(current);
    m_functiongraphmodel->setGraph(graph);
    m_sortedblocksmodel->sort(0);
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
