#include "functiongraphdialog.h"
#include "ui_functiongraphdialog.h"

FunctionGraphDialog::FunctionGraphDialog(QWidget *parent) : QDialog(parent), ui(new Ui::FunctionGraphDialog)
{
    ui->setupUi(this);
    ui->splitter->setStretchFactor(1, 1);
}

FunctionGraphDialog::~FunctionGraphDialog() { delete ui; }

void FunctionGraphDialog::setDisassembler(RDDisassembler* disassembler)
{
    if(ui->tbvFunctions->selectionMode())
        disconnect(ui->tbvFunctions->selectionModel(), &QItemSelectionModel::currentChanged, this, nullptr);

    m_functionlistmodel = new FunctionListModel(ui->tbvFunctions);
    m_functionlistmodel->setDisassembler(disassembler);

    m_functiongraphmodel = new FunctionGraphModel(disassembler, ui->tbvGraph);
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

    connect(ui->tbvFunctions->selectionModel(), &QItemSelectionModel::currentChanged, this, &FunctionGraphDialog::showGraph);
}

void FunctionGraphDialog::showGraph(const QModelIndex& current, const QModelIndex&)
{
    const RDGraph* graph = m_functionlistmodel->graph(current);
    m_functiongraphmodel->setGraph(graph);
    m_sortedblocksmodel->sort(0);
}
